import abc
import json
import datetime
import logging
import hashlib
import uuid
from optparse import OptionParser
from datetime import datetime, timedelta
from http.server import HTTPServer,BaseHTTPRequestHandler
from scoring import get_interests, get_score

SALT = "Otus"
ADMIN_LOGIN = "admin"
ADMIN_SALT = "42"
OK = 200
BAD_REQUEST = 400
FORBIDDEN = 403
NOT_FOUND = 404
INVALID_REQUEST = 422
INTERNAL_ERROR = 500
ERRORS = {
    BAD_REQUEST: "Bad Request",
    FORBIDDEN: "Forbidden",
    NOT_FOUND: "Not Found",
    INVALID_REQUEST: "Invalid Request",
    INTERNAL_ERROR: "Internal Server Error",
}
UNKNOWN = 0
MALE = 1
FEMALE = 2
GENDERS = {
    UNKNOWN: "unknown",
    MALE: "male",
    FEMALE: "female",
}

NULLABLE_VALUES = ['', {}, (), [], None]
SEVENTY_YEARS = timedelta(days=365)*70
SCORE_PAIRS = [('first_name','last_name'),('email','phone'),('birthday','gender')]


class ValidationError(Exception):
    pass


class BaseField(abc.ABC):

    def __init__(self, required=False, nullable=True):
        self.required = required
        self.nullable = nullable

    @abc.abstractmethod
    def validate(self, value):
        if self.required and value is None:
            raise ValidationError('%s is required'%(type(self).__name__,))
        if not self.nullable and value in NULLABLE_VALUES:
            raise ValidationError("%s can't be nullable"%(type(self).__name__,))


class CharField(BaseField):

    def validate(self, value):
        super().validate(value)
        if not isinstance(value,str):
            raise ValidationError("%s value type must be 'str'"%(type(self).__name__,))

class ArgumentsField(BaseField):

    def validate(self, value):
        super().validate(value)
        if not isinstance(value, dict):
            raise ValidationError("%s value type must be 'dict'"%(type(self).__name__,))


class EmailField(CharField):

    def validate(self, value):
        super().validate(value)
        if '@' not in value:
            raise ValidationError("%s must contain '@' character"%(type(self).__name__,))


class PhoneField(BaseField):

    def validate(self, value):
        super().validate(value)
        if not value:
            return
        if not (isinstance(value,int) or isinstance(value,str)):
            raise ValidationError("%s must be 'int' or 'str'"%(type(self).__name__,))
        if isinstance(value,str):
            try:
                int(value)
            except ValueError:
                raise ValidationError("%s must contain numbers only"%(type(self).__name__,))
        # We have an 'int'
        else:
            value = str(value)
        if len(value) != 11:
            raise ValidationError("%s length must be 11"%(type(self).__name__,))
        if not value.startswith('7'):
            raise ValidationError("%s must starts with 7"%(type(self).__name__,))


class DateField(CharField):

    def validate(self, value):
        super().validate(value)
        if not value:
            return
        try:
            return datetime.strptime(value, '%d.%m.%Y').date()
        except ValueError:
            raise ValidationError("%s must be in 'DD.MM.YYYY' format"%(type(self).__name__,))


class BirthDayField(DateField):

    def validate(self, value):
        parsed_date = super().validate(value)
        if parsed_date and (datetime.today().date() - parsed_date > SEVENTY_YEARS):
            raise ValidationError('%s date must be at most 70 years from now'%(type(self).__name__,))


class GenderField(BaseField):

    def validate(self, value):
        super().validate(value)
        if not isinstance(value,int):
            raise ValidationError("%s must be of type int"%(type(self).__name__,))
        if value not in GENDERS.keys():
            raise ValidationError("%s must be in [%s]"%(type(self).__name__,','.join(str(key) for key in GENDERS.keys())))



class ClientIDsField(BaseField):

    def validate(self, value):
        super().validate(value)
        if not isinstance(value,list):
            raise ValidationError("ClientIDs must be of type list")
        if value and not all(isinstance(ind,int) for ind in value):
            raise ValidationError("ClientIDs list must contain int values only")


class RequestMetaClass(type):

    def __new__(cls, name, bases, dct):
        actual_dct = dct.copy()
        actual_dct['_fields'] = {}
        for key, value in dct.items():
            if isinstance(value,BaseField):
                actual_dct['_fields'][key] = value
                del actual_dct[key]
        return super().__new__(cls, name, bases, actual_dct)


class RequestBase(metaclass=RequestMetaClass):
    def __init__(self, body):
        self.body = body
        self._errors = {}

    def validate(self):
        self._errors = {}
        for key, value in self._fields.items():
            if key not in self.body and not value.required:
                continue
            val = self.body.get(key)
            try:
                value.validate(val)
                setattr(self, key, val)
            except ValidationError as e:
                self._errors[key] = str(e)

    @property
    def errors(self):
        return self._errors

class ClientsInterestsRequest(RequestBase):
    client_ids = ClientIDsField(required=True, nullable=False)
    date = DateField(required=False, nullable=True)

    def get_result(self, is_admin, context, store):
        client_ids = getattr(self,'client_ids',[])
        context["nclients"] = len(client_ids)
        result = {}
        for client_id in client_ids:
            result[str(client_id)] = get_interests(store, client_id)
        return result


class OnlineScoreRequest(RequestBase):
    first_name = CharField(required=False, nullable=True)
    last_name = CharField(required=False, nullable=True)
    email = EmailField(required=False, nullable=True)
    phone = PhoneField(required=False, nullable=True)
    birthday = BirthDayField(required=False, nullable=True)
    gender = GenderField(required=False, nullable=True)

    def get_result(self, is_admin, context, store):
        context['has'] = [field for field in self._fields.keys() if getattr(self,field,None) not in NULLABLE_VALUES]
        score = 42 if is_admin else get_score(store, **{key:getattr(self,key,None) for key in self._fields.keys()})
        return {'score': score}

    def validate(self):
        super().validate()
        for pair in SCORE_PAIRS:
            if getattr(self,pair[0],None) not in NULLABLE_VALUES and getattr(self,pair[1],None) not in NULLABLE_VALUES:
                return

        self._errors["arguments"] = '%s needs to have at least one pair with not-null values: %s' % \
                                    (type(self).__name__,repr(SCORE_PAIRS),)


class MethodRequest(RequestBase):
    account = CharField(required=False, nullable=True)
    login = CharField(required=True, nullable=True)
    token = CharField(required=True, nullable=True)
    arguments = ArgumentsField(required=True, nullable=True)
    method = CharField(required=True, nullable=True)

    @property
    def is_admin(self):
        return self.login == ADMIN_LOGIN


def check_auth(request):
    if request.is_admin:
        digest = hashlib.sha512(bytes(datetime.now().strftime("%Y%m%d%H") + ADMIN_SALT,"utf-8")).hexdigest()
    else:
        digest = hashlib.sha512(bytes(request.account + request.login + SALT,"utf-8")).hexdigest()
    if digest == request.token:
        return True
    return False


def method_handler(request, ctx, store):
    method_request = MethodRequest(request['body'])
    method_request.validate()
    if method_request.errors:
        return method_request.errors, INVALID_REQUEST

    if not check_auth(method_request):
        return 'Authentication failed for user "%s"'%(method_request.login,), FORBIDDEN

    request_classes = {
        'online_score': OnlineScoreRequest,
        'clients_interests': ClientsInterestsRequest
    }

    if method_request.method not in request_classes:
        return "Method '%s' not found"%(method_request.method,), NOT_FOUND

    r = request_classes[method_request.method](method_request.arguments)
    r.validate()
    result = r.get_result(method_request.is_admin, ctx, store)

    if r.errors:
        return r.errors, INVALID_REQUEST
    return result, OK



class MainHTTPHandler(BaseHTTPRequestHandler):
    router = {
        "method": method_handler
    }
    store = None

    def get_request_id(self, headers):
        return headers.get('HTTP_X_REQUEST_ID', uuid.uuid4().hex)

    def do_POST(self):
        response, code = {}, OK
        context = {"request_id": self.get_request_id(self.headers)}
        request = None
        try:
            data_string = self.rfile.read(int(self.headers['Content-Length']))
            request = json.loads(data_string)
        except:
            code = BAD_REQUEST

        if request:
            path = self.path.strip("/")
            logging.info("%s: %s %s" % (self.path, data_string, context["request_id"]))
            if path in self.router:
                try:
                    response, code = self.router[path]({"body": request, "headers": self.headers}, context, self.store)
                except Exception as e:
                    logging.exception("Unexpected error: %s" % e)
                    code = INTERNAL_ERROR
            else:
                code = NOT_FOUND

        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        if code not in ERRORS:
            r = {"response": response, "code": code}
        else:
            r = {"error": response or ERRORS.get(code, "Unknown Error"), "code": code}
        context.update(r)
        logging.info(context)
        self.wfile.write(json.dumps(r).encode('utf-8'))
        return


if __name__ == "__main__":
    op = OptionParser()
    op.add_option("-p", "--port", action="store", type=int, default=8080)
    op.add_option("-l", "--log", action="store", default=None)
    (opts, args) = op.parse_args()
    logging.basicConfig(filename=opts.log, level=logging.INFO,
                        format='[%(asctime)s] %(levelname).1s %(message)s', datefmt='%Y.%m.%d %H:%M:%S')
    server = HTTPServer(("localhost", opts.port), MainHTTPHandler)
    logging.info("Starting server at %s" % opts.port)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    server.server_close()
