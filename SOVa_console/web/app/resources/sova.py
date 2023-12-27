from flask_restx import Resource, Namespace, fields, reqparse
import os.path
import shutil
from os import listdir 
from base64 import b64encode
from datetime import datetime
import werkzeug
from ..models.models import SIB
from ..models import db


ns = Namespace("api")

sib_model = ns.model('SIB', {
    'date'   : fields.String,
    'point'  : fields.String,
    'module' : fields.String,
    'data'   : fields.String
}) 

@ns.route("/sib")
class SIBListResource(Resource):
    def get(self):
        sibs = SIB.query.all()
        data = {}

        for sib in sibs:
            data[sib.index] = {
                'date'   : str(sib.date),
                'point'  : sib.point,
                'module' : sib.module,
                'data'   : sib.data
            }
        return data

    @ns.expect(sib_model)
    def post(self):
        new_sib = ns.payload
        
        sib = SIB(
            date = new_sib['date'],
            point = new_sib['point'],
            module = new_sib['module'],
            data = new_sib['data']
        )
        
        db.session.query(SIB)
        db.session.add(sib)
        db.session.commit()
        
        return '', 201
    
@ns.route("/sib/<int:index>")
class SIBResource(Resource):
    @ns.marshal_with(sib_model)
    def get(self, index):
        sib = SIB.query.filter_by(index=index).first()
        data = {}
        data[sib.index] = {
                'date'   : str(sib.date),
                'point'  : sib.point,
                'module' : sib.module,
                'data'   : sib.data
        }

        return data

@ns.route("/is_update_yara/<string:filename>")
class YaraIsUpdateResource(Resource):
    def get(self, filename):
        fname = filename
        return os.path.isfile(f'/app/yara/{fname}')
    
@ns.route("/update_yara")
class YaraUpdate(Resource):
    def get(self):
        
        data = {}
        fname = listdir('/app/yara/')[0]
        
        with open(f'/app/yara/{fname}') as file:
            rules = file.read()
            rules = b64encode(rules.encode('utf-8')).decode('utf-8')
            data = {
                'name' : fname,
                'content' : rules
            }
            return data

file_upload = reqparse.RequestParser()
file_upload.add_argument('file',
                         type=werkzeug.datastructures.FileStorage, 
                         location='files', 
                         required=True, 
                         help='Document 1')

@ns.route("/upload_yara")
class YaraUpload(Resource):
    def get():
        pass
    
    @ns.expect(file_upload)
    def post(self):
        args = file_upload.parse_args()
        
        folder = '/app/yara/'
        for filename in os.listdir(folder):
            file_path = os.path.join(folder, filename)
            try:
                if os.path.isfile(file_path) or os.path.islink(file_path):
                    os.unlink(file_path)
                elif os.path.isdir(file_path):
                    shutil.rmtree(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))
        
        args['file'].save(os.path.join('/app/yara/', datetime.now().strftime("%d-%m-%Y_%H-%M-%S.yar")))
        a = args['file']
        print(a)
        return {'status': 'Done'}, 200
    
            
         
            
        
    