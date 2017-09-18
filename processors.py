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
