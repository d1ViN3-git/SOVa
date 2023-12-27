from .sova import ns as sova_api
from flask import Blueprint, make_response
from flask_restx import Api

blueprint = Blueprint("v1", __name__)

api = Api(blueprint, doc="/doc", title="FLASK RESTX API", default_mediatype="application/xml")
api.add_namespace(sova_api)

