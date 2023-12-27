from flask import redirect, url_for, request, session
from flask_login import current_user
from flask_admin.contrib.sqla import ModelView
from flask_admin.contrib.sqla.filters import BaseSQLAFilter
from ..models.models import SIB

class FilterByClass(BaseSQLAFilter):
    def apply(self, query, value, alias=None):
        return query.filter(SIB.point == value)
    def operation(self):
        return u'equals'

class SIBModelView(ModelView):
    def is_accessible(self):
        return current_user.is_authenticated

    def inaccessible_callback(self, name, **kwargs):
        if not self.is_accessible():
            return redirect(url_for('login', next=request.url))
        
    column_searchable_list = ('point', 'module')
    column_list = ('index', 'date', 'point', 'module', 'data')
    column_labels = {
        'index' : 'Номер',
        'date' : 'Дата',
        'point' : 'Место сработки',
        'module' : 'Модуль',
        'data' : 'Доп. инфо'
    }
    can_create = False
    can_edit = False
    can_delete = False
	# allowed_search_types = (StringField, models.LowerStringField)
    # column_filters = [ FilterByClass('cls', 'Класс центра', [('A', 'A'), ('Б', 'Б'), ('В', 'В')]) ]