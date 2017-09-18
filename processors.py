# coding=utf8
from __future__ import unicode_literals

import os
import random
import json
from datetime import timedelta, date
from pyunpack import Archive
from transliterate import translit
from shapefile import ShapefileException, Reader
from shapely.geometry import asShape, Polygon
from subprocess import check_output, CalledProcessError

from django.utils import six
from django.utils.crypto import constant_time_compare, salted_hmac
from django.utils.http import base36_to_int, int_to_base36
from django.utils import timezone
from django.db.models import Min
from django.core.cache import cache
from django.core.mail import send_mail
from django.contrib.auth.tokens import PasswordResetTokenGenerator
from django.conf import settings
from django.utils.http import urlsafe_base64_encode
from django.template import loader
from django.utils.encoding import force_bytes
from flyber_auth.models import Subscription, User as CustomUser

from .models import (Order, Bid, OrderParameters, Coordinate,
                     CancelOrderReasons, CancelOrderLog, Results, Region, OrderRating)
from .exceptions import (TooEarlyOrderResolve, OrderAlreadyResolve,
                         IncorrectOrderStatus, OperatorNotParticipate,
                         OrderNotRemoved, OrderNotResolve,
                         GeodataFilesIsNotSupported, GeodataFilesNotFound,
                         GeodataArchiveIsNotSupported,
                         GeodataFileConvertError, GeodataTooManyPolygons,
                         GeodataFilesTooMany)


class Criterion(object):
    """
    Базовый класс критерия оценки. Служит для вычисления лучшего значения
    критерия в наборе данных и оценки значения из набора данных, как отношения
    лучшего значения и данного.
    """
    def __init__(self, name, weight, data_set):
        self.name = name
        self.weight = weight
        self.best = self._get_best(data_set)

    def _get_best(self, data_set):
        raise NotImplementedError

    def get_score(self, value):
        raise NotImplementedError


class PositiveCriterion(Criterion):
    """
    Критерий оценки, где большие значения соответствуют наилучшему значению
    """

    def _get_best(self, data_set):
        return max(i[self.name] for i in data_set)

    def get_score(self, value):
        return (float(value) / float(self.best)) * self.weight


class NegativeCriterion(Criterion):
    """
    Критерий оценки, где меньшие значения соответствуют наилучшему значению
    """

    def _get_best(self, data_set):
        return min(i[self.name] for i in data_set)

    def get_score(self, value):
        return (float(self.best) / float(value)) * self.weight


class OptimalDecisionProcessor(object):
    """
    Класс, осуществляющий оптимальный выбор по нескольким критериям.
    """

    def __init__(self, criteria, data_set):
        """
        :param criteria: коллекция используемых критериев
        :param: data_set: список словарей с данными, по которым осуществляется
        выбор
        """
        self.criteria = criteria
        self.data_set = data_set

    def get_item_score(self, item):
        criteria_scores = []
        for criterion in self.criteria:
            criterion_score = criterion.get_score(item[criterion.name])
            criteria_scores.append(criterion_score)

        return sum(criteria_scores)

    def calculate_scores(self):
        for item in self.data_set:
            item['score'] = self.get_item_score(item)

    def ranging_by_scores(self):
        self.calculate_scores()
        return sorted(self.data_set, key=lambda i: i['score'], reverse=True)

    def get_optimal(self):
        self.calculate_scores()
        return max(self.data_set, key=lambda i: i['score'])


class BestBidSelector(object):
    """
    Класс для автоматического выбора наилучшего предложения подрядчика
    """

    PRICE_CRITERION_NAME = 'price'
    DEADLINE_CRITERION_NAME = 'deadline'

    def __init__(self, bids):
        bids_data_set = self.get_bids_data_set(bids)
        price_criterion = NegativeCriterion(name=self.PRICE_CRITERION_NAME,
                                            weight=0.5,
                                            data_set=bids_data_set)
        deadline_criterion = NegativeCriterion(
            name=self.DEADLINE_CRITERION_NAME,
            weight=0.5,
            data_set=bids_data_set)
        criteria = (price_criterion, deadline_criterion)
        self.decision_processor = OptimalDecisionProcessor(
            criteria,
            bids_data_set)

    def get_best_bid(self):
        best_bid_id = self.decision_processor.get_optimal()['id']
        return Bid.objects.get(pk=best_bid_id)

    def get_bids_data_set(self, bids):
        bid_data_list = []
        for bid in bids:
            bid_data = self.get_bid_data(bid)
            bid_data_list.append(bid_data)
        return bid_data_list

    def get_bid_data(self, bid):
        return {
            'id': bid.id,
            self.PRICE_CRITERION_NAME: bid.price,
            self.DEADLINE_CRITERION_NAME: bid.get_days_to_deadline()
        }

    @staticmethod
    def get_best_bid_price(bids):
        return bids.aggregate(Min('price'))['price__min']

    @staticmethod
    def is_best(bids, user_bids):
        best_price = bids.aggregate(Min('price'))['price__min']
        user_price = user_bids.aggregate(Min('price'))['price__min']
        return True if user_price <= best_price else False

    @staticmethod
    def get_best_bid_deadline(bids):
        return bids.aggregate(Min('deadline'))['deadline__min']


class TenderProcessor(object):
    HOURS_TO_AUTO_RESOLVE = 72
    HOURS_TO_MANUAL_RESOLVE = 24
    HOURS_TO_DRAFT_REMOVE = 24

    # Validate section
    @classmethod
    def _resolve_common_validate(cls, order):
        if order.status != Order.OPEN:
            raise IncorrectOrderStatus

    @classmethod
    def _resolve_by_author_validate(cls, order):
        cls._resolve_common_validate(order)
        hours = cls.HOURS_TO_MANUAL_RESOLVE
        if order.pub_date + timedelta(hours=hours) > timezone.now():
            raise TooEarlyOrderResolve
        if order.winning_bid is not None:
            raise OrderAlreadyResolve

    @classmethod
    def _auto_resolve_validate(cls, order):
        cls._resolve_common_validate(order)
        hours = cls.HOURS_TO_AUTO_RESOLVE
        if order.pub_date + timedelta(hours=hours) > timezone.now():
            raise TooEarlyOrderResolve

    @classmethod
    def _cancel_by_customer_validate(cls, order):
        if order.status not in (Order.OPEN, Order.IN_PROCESS):
            raise IncorrectOrderStatus

    @classmethod
    def _reopen_by_customer_validate(cls, order):
        if order.status != Order.CANCELED:
            raise IncorrectOrderStatus
        if not order.resolve_reason:
            raise IncorrectOrderStatus

    @classmethod
    def _cancel_by_operator_validate(cls, order, operator):
        if order.status not in (Order.OPEN, Order.IN_PROCESS):
            raise IncorrectOrderStatus
        if not order.get_participation(operator):
            raise OperatorNotParticipate

    @classmethod
    def _confirm_validate(cls, order):
        if order.status != Order.DRAFT:
            raise IncorrectOrderStatus

    @classmethod
    def operator_results_validate(cls, order, operator):
        try:
            winning_operator = order.winning_bid.operator
        except AttributeError:
            raise OrderNotResolve
        if order.status != Order.IN_WORK:
            raise IncorrectOrderStatus
        if winning_operator != operator:
            raise OperatorNotParticipate

    @classmethod
    def _get_results_by_customer_validate(cls, order, customer):
        return order.status == Order.DONE and order.customer == customer

    @classmethod
    def _change_status_by_operator_validate(cls, order):
        if order.status != Order.IN_WORK:
            raise IncorrectOrderStatus

    # Actions section
    @classmethod
    def _cancel_order_log(cls, order, request):
        user = request.user
        reasons_list = request.data.get('reasons_list', [])
        other_reason = request.data.get('other_reason', None)
        reasons = CancelOrderReasons.objects.filter(pk__in=reasons_list)
        reason = ' ### Причины не были указаны.'
        if reasons.exists():
            reason = ' ### '.join([i.text_reason for i in reasons])
        if other_reason is not None:
            reason += ' ### {}'.format(other_reason)
        CancelOrderLog.objects.create(user=user, order=order,
                                      reason=reason)

    @classmethod
    def _cancel_by_system(cls, order):
        order.status = Order.CANCELED
        order.resolve_reason = Order.AUTO_RESOLVED
        order.save()
        cls._cancel_order_bids(order, Bid.AUTO_CANCEL)

    @classmethod
    def _cancel_by_customer(cls, order):
        if order.status == Order.OPEN:
            order.resolve_reason = Order.MANUAL_RESOLVED
        if order.status == Order.IN_PROCESS:
            order.resolve_reason = Order.CUSTOMER_REFUSED
        order.status = Order.CANCELED
        order.save()
        cls._cancel_order_bids(order, Bid.CUSTOMER_CANCEL)

    @classmethod
    def _clone_order_relationship(cls, old_order, new_order):
        for queryset in (old_order.order_parameters_set.all(),
                         old_order.coordinates.all()):
            for obj in queryset:
                obj.pk = None
                obj.order = new_order
                obj.save()

    @classmethod
    def _clone_order(cls, order):
        old_order = Order.objects.get(pk=order.pk)
        order.pk = None
        cls._update_order(order)
        try:
            cls._clone_order_relationship(old_order=old_order, new_order=order)
            return order
        except (Coordinate.DoesNotExist, OrderParameters.DoesNotExist) as _:
            return order

    @classmethod
    def _update_order(cls, order):
        order.status = Order.OPEN
        order.resolve_reason = ''
        order.pub_date = timezone.now()
        order.planned_from = timezone.now()
        order.planned_to = timezone.now()
        order.save()
        return order

    @classmethod
    def _reopen_by_customer(cls, order):
        if order.resolve_reason == Order.AUTO_RESOLVED:
            return cls._update_order(order)
        else:
            return cls._clone_order(order)

    @classmethod
    def _cancel_operator_bids(cls, order, operator):
        bid = operator.bid_set.filter(order=order).order_by('-pub_date')[0]
        bid.opened = False
        bid.close_reason = Bid.OPERATOR_CANCEL
        bid.save()
        return bid

    @classmethod
    def _cancel_order_by_operator(cls, order, operator):
        order.status = Order.CANCELED
        order.resolve_reason = Order.OPERATOR_RESOLVED
        order.save()
        cls._cancel_operator_bids(order, operator)

    @classmethod
    def _resolve_by_system(cls, order):
        bid_selector = BestBidSelector(order.get_actual_bids())
        bid = bid_selector.get_best_bid()
        order.winning_bid = bid
        order.status = Order.IN_PROCESS
        order.save()

    @classmethod
    def _cancel_order_bids(cls, order, close_reason):
        order.bids.update(opened=False, close_reason=close_reason)

    @classmethod
    def resolve_by_author(cls, order, bid):
        cls._resolve_by_author_validate(order)
        order.winning_bid = bid
        order.status = Order.IN_PROCESS
        order.resolve_reason = Order.MANUAL_RESOLVED
        order.save()
        cls._cancel_order_bids(order, Bid.CUSTOMER_CANCEL)

    @classmethod
    def auto_resolve(cls, order):
        cls._auto_resolve_validate(order)
        if not order.get_actual_bids():
            cls._cancel_by_system(order)
        else:
            cls._resolve_by_system(order)

    @classmethod
    def auto_remove(cls, order):
        if not order.delete():
            raise OrderNotRemoved

    @classmethod
    def cancel_by_operator(cls, order, request):
        operator = request.user
        cls._cancel_by_operator_validate(order, operator)
        if order.status == Order.OPEN:
            bid = cls._cancel_operator_bids(order, operator)
            cls._cancel_order_log(order, request)
            return bid
        elif (order.status == Order.IN_PROCESS and
              order.winning_bid.operator == operator):
            cls._cancel_order_by_operator(order, operator)
            cls._cancel_order_log(order, request)
        else:
            raise IncorrectOrderStatus

    @classmethod
    def cancel_by_customer(cls, order, request):
        cls._cancel_by_customer_validate(order)
        cls._cancel_by_customer(order)
        cls._cancel_order_log(order, request)

    @classmethod
    def reopen_by_customer(cls, order):
        cls._reopen_by_customer_validate(order)
        return cls._reopen_by_customer(order)

    @classmethod
    def confirm(cls, order):
        cls._confirm_validate(order)
        order.status = Order.OPEN
        order.save()

    @classmethod
    def accept_bid(cls, order, bid):
        order.winning_bid = bid
        order.status = Order.IN_PROCESS
        order.save()

    @classmethod
    def get_results_by_customer(cls, order, customer):
        if cls._get_results_by_customer_validate(order, customer):
            return order.results.filter(status=Results.CONFIRMED)

    @classmethod
    def change_status_by_operator(cls, order):
        cls._change_status_by_operator_validate(order)
        order.status = Order.VERIFICATION
        order.save()



class OrderPriceCalculator(object):
    def __init__(self, order):
        self.order = order

    def get_quantitative_factor(self, value, value_max, base_factor):
        try:
            final_factor = float(value) / float(value_max) * base_factor
        except ZeroDivisionError:
            return 0

        return final_factor

    def get_overlap_factor(self):
        # TODO: Уточнить как задавать коэффициенты
        base_overlap_factor = 0.5

        overlap_factor = self.get_quantitative_factor(
            self.order.overlap_percentage,
            self.order.MAX_OVERLAP_PERCENTAGE,
            base_overlap_factor)
        return overlap_factor

    def get_scale_factor(self):
        return float(self.order.scale.increase_factor)

    def get_order_type(self):
        return self.order.order_type

    def get_photo_types_factor(self):
        sum_format = sum(self.order.photo_types.values_list(
            'increase_factor', flat=True))
        return float(sum_format)

    def get_output_format_types_factor(self):
        sum_format = sum(self.order.output_format_types.values_list(
            'increase_factor', flat=True))
        return float(sum_format)

    def get_estimated_price(self):
        if hasattr(self.order, 'geodata'):
            sector_price = self.get_sector_price()
            sectors_count = self.order.geodata.sectors
            return sector_price * sectors_count
        else:
            return None

    def get_sector_price(self):
        # TODO: Уточнить как задавать коэффициенты
        base_price_segment = 1000

        # TODO: Закомментировано из-за изменений структуры параметров
        # factors_sum = 0.0

        # factors_sum += self.get_overlap_factor()
        # factors_sum += self.get_scale_factor()
        # factors_sum += self.get_photo_types_factor()
        # factors_sum += self.get_output_format_types_factor()

        # final_price = base_price_segment + base_price_segment * factors_sum
        # return final_price

        return base_price_segment


class Geometry(object):
    """
    Класс для работы с полигонами на координатной плоскости.
    """

    GEOJSON_FILE = 'regionsGeoJson.json'

    @classmethod
    def set_regions_for_order(cls, order_id):
        """Добавление соответсвующих регионов к заказу при сохранении.

        :param order_id: id заказа.
        """

        order = Order.objects.get(pk=order_id)
        coordinates = list(
            order.coordinates.values_list('longitude', 'latitude'))
        if len(coordinates) > 2:
            regions_id = cls.polygons_intersection(coordinates)
            order.regions.set(Region.objects.filter(pk__in=regions_id))
        else:
            order.regions.clear()

    @classmethod
    def geojson_file_to_polygons(cls, geojson_file):
        """Получение полгигонов адм. единиц РФ.

        :param geojson_file: Файл в формате GeoJSON.
        :return: Список из OSM_ID регионов и соответсвующих им полигонов.
        """

        with open(geojson_file) as data:
            regions = json.load(data)
            data.close()
            return [(x['properties']['OSM_ID'], asShape(x['geometry']))
                    for x in regions['features']]

    @classmethod
    def polygons_intersection(cls, coordinates):
        """Определение пересечения полигона и адм. единиц РФ.

        :param coordinates: Координаты полигона выделенного заказчиком.
        :return: Список OSM_ID регионов.
        """

        regions_from_cache = cache.get_or_set(
            'regions', cls.geojson_file_to_polygons(cls.GEOJSON_FILE))
        polygon = Polygon(coordinates)

        filtered_regions = filter(lambda x: polygon.intersection(x[1]),
                                  regions_from_cache)

        return dict(filtered_regions).keys()


class GeodataConverter:
    """
    Класс для обработки загружаемых геоданных.
    """
    SUPPORT_GEODATA_UPLOAD = ('.kml', '.kmz', '.7z', '.zip')
    SUPPORT_GEODATA_ARCHIVE = ('.kmz', '.7z', '.zip')
    SUPPORT_GEODATA_FILES = ('.kml', '.shp')
    MAX_GEODATA_FILES_IN_REQ = 1
    MAX_POLYGONS_IN_GEODATA = 1
    ERROR_MESSAGES = {
        0: "Для загрузки разрешены только KML, KMZ, ZIP и 7z.",
        1: "Системе не удалось открыть архив, возможно архив поврежден.",
        2: "Системе не удалось сконвертировать SHP/KML файлы в полигон.",
        3: "Файл должен содержать координаты только для одного полигона.",
        4: "Загружаемый файл должен быть не более 100 мб."
    }

    def __init__(self, file_name):
        file_ext = self._get_file_ext(file_name)
        if not (file_ext in self.SUPPORT_GEODATA_UPLOAD):
            raise GeodataFilesIsNotSupported(self.ERROR_MESSAGES[0])
        self.geodata_file = self._unpack(file_name) \
            if file_ext in self.SUPPORT_GEODATA_ARCHIVE else file_name

    @property
    def coordinates(self):
        ext = self._get_file_ext(self.geodata_file)
        if ext == '.kml':
            return self._kml_to_geojson()
        if ext == '.shp':
            return self._shp_to_geojson()

    def _ls_geodata_files(self, unpack_dir):
        files = os.listdir(unpack_dir)
        geodata_files = [unpack_dir + x for x in files
                         if x.lower().endswith(self.SUPPORT_GEODATA_FILES)
                         ]
        return geodata_files, len(geodata_files)

    def _unpack(self, file_name):
        unpack_dir = self._get_temporary_path()
        try:
            Archive(file_name).extractall(unpack_dir, auto_create_dir=True)
        except (ValueError, TypeError):
            raise GeodataArchiveIsNotSupported(self.ERROR_MESSAGES[1])
        geodata_files, count = self._ls_geodata_files(unpack_dir)
        if count == self.MAX_GEODATA_FILES_IN_REQ:
            return geodata_files[0]
        elif count > self.MAX_GEODATA_FILES_IN_REQ:
            raise GeodataFilesTooMany(self.ERROR_MESSAGES[3])
        raise GeodataFilesNotFound(self.ERROR_MESSAGES[1])

    def _get_file_ext(self, file_name):
        return os.path.splitext(file_name)[1].lower()

    def _get_temporary_path(self):
        random_part = ''.join([random.choice(list(
            '123456789qwertyuiopasdfghjklzxcvbnm')) for _ in range(12)]) + '/'
        temporary_path = settings.UPLOAD_DIR + random_part
        return temporary_path

    def _shp_to_geojson(self):
        """Обработка Shape-архива и преобразование в GeoJSON."""

        try:
            geojson_data = self._parse_shp_data(Reader(self.geodata_file))
            return self._get_coordinates({'features': geojson_data})
        except (TypeError, IndexError, ShapefileException):
            raise GeodataFileConvertError(self.ERROR_MESSAGES[2])

    def _get_geojson_fields(self, shp_fields):
        geojson_fields = [field[0] for field in shp_fields[1:]]
        return geojson_fields

    def _parse_shp_data(self, reader_shp_file):
        geojson_fields = self._get_geojson_fields(reader_shp_file.fields)
        geojson_data = []
        for sr in reader_shp_file.shapeRecords():
            atr = dict(zip(geojson_fields, sr.record))
            geom = sr.shape.__geo_interface__
            geojson_data.append(dict(type="Feature", geometry=geom,
                                     properties=atr))
        return geojson_data

    def _kml_to_geojson(self):
        """Преобразование KML файла в GeoJSON."""

        try:
            geojson_data = check_output(["togeojson", self.geodata_file])
        except CalledProcessError:
            raise GeodataFileConvertError(self.ERROR_MESSAGES[2])
        return self._get_coordinates(json.loads(geojson_data))

    def _get_coordinates(self, geojson):
        polygons = [x['geometry']['coordinates'] for x in geojson['features']
                    if x.get('geometry', {}).get('type', '') == 'Polygon']
        if not polygons:
            raise GeodataFileConvertError(self.ERROR_MESSAGES[2])
        if len(polygons) > self.MAX_POLYGONS_IN_GEODATA:
            raise GeodataTooManyPolygons(self.ERROR_MESSAGES[3])
        if len(polygons[0]) > self.MAX_POLYGONS_IN_GEODATA:
            raise GeodataTooManyPolygons(self.ERROR_MESSAGES[3])
        try:
            coordinate = [{"latitude": x[1], "longitude": x[0]}
                          for x in polygons[0][0]]
            return coordinate
        except IndexError:
            raise GeodataFileConvertError(self.ERROR_MESSAGES[2])


class Notification(object):

    @classmethod
    def template_password_change(cls):
        template = "notifications/email/email_notification_change_password_" \
                   "success.html"
        simple_template = "notifications/email/email_notification_change_" \
                          "password_success.txt"

        subject = "Пароль упешно изменен"
        plain_message = loader.render_to_string(simple_template)
        html_message = loader.render_to_string(template)

        return {"subject": subject, "plain_message": plain_message,
                "html_message": html_message}

    @classmethod
    def notification_rate_order(cls, order_id):
        order = Order.objects.get(pk=order_id)
        email = order.customer
        subject = "Оцените заказ"
        context = {
            "email": email,
            "order_id": order.pk,
            "domain": settings.DOMAIN
        }
        template = "notifications/email/email_notification_estimate_order.html"
        simple_template = "notifications/email/email_notification_estimate_order.txt"

        plain_message = loader.render_to_string(simple_template, context=context)
        html_message = loader.render_to_string(template, context=context)

        send_mail(subject, plain_message, settings.EMAIL_HOST_USER, [email],
              html_message=html_message)


    @classmethod
    def notification_new_order_event(cls, order_id):
        """Оповещение пользователей о новых заказах.

        :param order_id: id заказа.
        """

        order = Order.objects.get(pk=order_id)
        active_subscr = Subscription.objects.filter(status=True).filter(
            regions__in=order.regions.all())
        email_for_notification = active_subscr.values_list(
            'profile__user__email', flat=True)

        region_list = order.regions.all().values_list('name', flat=True)
        region = ", ".join(region_list)
        c = {
            'order': order.__unicode__(),
            'region': region
        }
        subject_template_name = "notifications/email/new_order.txt"
        email_template_name = "notifications/email/new_order.html"
        subject = loader.render_to_string(subject_template_name, c)
        subject = ''.join(subject.splitlines())
        html_email = loader.render_to_string(email_template_name, c)
        send_mail(subject,
                  'Новый заказ: %s (%s)' % (c['order'], c['region']),
                  settings.DEFAULT_FROM_EMAIL,
                  email_for_notification,
                  fail_silently=True,
                  html_message=html_email)


    @classmethod
    def notification_reset_password_event(cls, user_id, domain):
        user = CustomUser.objects.get(pk=user_id)
        c = {
            'email': user.email,
            'domain': domain,
            'site_name': 'www.flyber.ru',
            'uid': urlsafe_base64_encode(force_bytes(user.pk)),
            'user': user,
            'token': password_reset_token_generator.make_token(user),
            'protocol': 'http',
        }

        subject_template_name = "notifications/email/password_reset_subject.txt"
        email_template_name = "notifications/email/password_reset.html"

        subject = loader.render_to_string(subject_template_name, c)
        subject = ''.join(subject.splitlines())
        html_email = loader.render_to_string(email_template_name, c)
        send_mail(subject,
                  'http://%s/reset_password/?user_checkword=%s-%s' %
                  (settings.DOMAIN, c['uid'], c['token']),
                  settings.DEFAULT_FROM_EMAIL,
                  [user.email],
                  fail_silently=True,
                  html_message=html_email)


class EmailConfirmationTokenGenerator(object):
    """
    Strategy object used to generate and check tokens for the email
    confirmation mechanism.
    """

    key_salt = "django.contrib.auth.tokens.EmailConfirmationTokenGenerator"

    def make_token(self, user):
        """
        Returns a token that can be used once to do a email confirm
        for the given user.
        """
        return self._make_token_with_timestamp(user, self._num_days(
            self._today()))

    def _make_token_with_timestamp(self, user, timestamp):
        ts_b36 = int_to_base36(timestamp)
        hash = salted_hmac(
            self.key_salt,
            self._make_hash_value(user, timestamp),
        ).hexdigest()[::2]
        return "%s-%s" % (ts_b36, hash)

    def check_token(self, user, token):
        """
        Check that a email confirm token is correct for a given user.
        """
        # Parse the token
        try:
            ts_b36, hash = token.split("-")
        except ValueError:
            return False

        try:
            ts = base36_to_int(ts_b36)
        except ValueError:
            return False

        # Check that the timestamp/uid has not been tampered with
        if not constant_time_compare(
                self._make_token_with_timestamp(user, ts), token):
            return False

        # Check the timestamp is within limit
        if (self._num_days(self._today()) - ts) > \
                settings.EMAIL_CONFIRM_TIMEOUT_DAYS:
            return False

        return True

    def _make_hash_value(self, user, timestamp):
        joined_timestamp = '' if user.date_joined is None else \
            user.date_joined.replace(microsecond=0, tzinfo=None)
        return (
            six.text_type(user.pk) + user.password +
            six.text_type(joined_timestamp) + six.text_type(timestamp)
        )

    def _num_days(self, dt):
        return (dt - date(2001, 1, 1)).days

    def _today(self):
        # Used for mocking in tests
        return date.today()
