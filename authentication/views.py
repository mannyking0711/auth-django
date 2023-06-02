from django.db.models import F, Sum, Count
from django.http import JsonResponse
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .models import CustomUser, ScanRequest, Vulnerability, OpenPort
from .serializers import MyTokenObtainPairSerializer, CustomUserSerializer, ScanRequestSerializer
from .service import startScan, stopScan, getScanResult


class ObtainTokenPairWithColorView(TokenObtainPairView):
    serializer_class = MyTokenObtainPairSerializer

    def post(self, request, *args, **kwargs):
        # With Google
        if request.data.get('sub') is not None:
            request.data['password'] = request.data['sub']
            request.data['username'] = request.data['name']

            try:
                return super(TokenObtainPairView, self).post(request)
            except:
                serializer = CustomUserSerializer(data=request.data)
                if serializer.is_valid():
                    user = serializer.save()
                    return super(TokenObtainPairView, self).post(request)

        # With Email
        try:
            currentUser = CustomUser.objects.get(email=request.data['email'])

            try:
                return super(TokenObtainPairView, self).post(request)
            except:
                return Response('Password does not match', status=status.HTTP_400_BAD_REQUEST)
        except:
            return Response('Email does not exist, please sign up before login', status=status.HTTP_400_BAD_REQUEST)


class CustomUserCreate(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request, format='json'):
        serializer = CustomUserSerializer(data=request.data)
        if serializer.is_valid():
            try:
                currentUser = CustomUser.objects.get(email=request.data['email'])
                if (currentUser):
                    return Response('Email already exists', status=status.HTTP_400_BAD_REQUEST)
            except:
                user = serializer.save()
                if user:
                    json = serializer.data
                    return Response(json, status=status.HTTP_201_CREATED)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class LogoutAndBlacklistRefreshTokenForUserView(APIView):
    permission_classes = (permissions.AllowAny,)
    authentication_classes = ()

    def post(self, request):
        try:
            refresh_token = request.data["refresh_token"]
            token = RefreshToken(refresh_token)
            token.blacklist()
            return Response(status=status.HTTP_205_RESET_CONTENT)
        except Exception as e:
            return Response(status=status.HTTP_400_BAD_REQUEST)


class HelloWorldView(APIView):

    def get(self, request):
        return Response(data={"hello": request.user.id}, status=status.HTTP_200_OK)


class ScanRequestView(APIView):

    def get(self, request, uuid):
        try:
            scan = ScanRequest.objects.get(track=uuid)

            if len(scan.result) != 0:
                return Response(data=eval(scan.result), status=status.HTTP_200_OK)

            try:
                result = getScanResult(uuid)
                if len(scan.result) == 0:
                    scan.result = result
                    scan.save()

                    # Scan result analysis
                    for host in result.get('hosts'):
                        vulnerability = Vulnerability(request=scan)
                        vulnerability.subdomain = host.get('name')
                        for vul in host.get('vulnerabilities'):
                            if vul['severity'] == 'info':
                                vulnerability.info += 1
                            elif vul['severity'] == 'low':
                                vulnerability.low += 1
                            elif vul['severity'] == 'medium':
                                vulnerability.medium += 1
                            elif vul['severity'] == 'critical':
                                vulnerability.critical += 1

                        vulnerability.save()

                        ports = {}
                        for portObj in host.get('ports'):
                            if portObj['state']['@state'] != 'open':
                                continue
                            port = portObj['@portid']
                            if ports.get(port) is None:
                                ports.setdefault(port, 0)
                            ports[port] = ports[port] + 1

                        for port in ports.keys():
                            openport = OpenPort(request=scan, subdomain=host.get('name'), port=port)
                            openport.save()

                return Response(data=result, status=status.HTTP_200_OK)
            except ConnectionError as err:
                return Response(data={
                    'message': err.args[0]
                }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
            except RuntimeError as err:
                return Response(data={
                    'message': err.args[0]
                }, status=status.HTTP_400_BAD_REQUEST)

        except ScanRequest.DoesNotExist:
            return Response(data="Track does not exist", status=status.HTTP_404_NOT_FOUND)

    def post(self, request, format='json'):
        domain = request.data['domain']

        try:
            apiRes = startScan(domain)
            scan = ScanRequest.objects.create(user=request.user, domain=request.data['domain'], track=apiRes)
            scan.save()
            return Response(data={"track": scan.track}, status=status.HTTP_200_OK)
        except ConnectionError as err:
            return Response(data={
                'message': err.args[0]
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as err:
            return Response(data={
                'message': err.args[0]
            }, status=status.HTTP_400_BAD_REQUEST)

    def delete(self, request):
        track = request.query_params['track']

        try:
            apiRes = stopScan(track)
        except ConnectionError as err:
            return Response(data={
                'message': err.args[0]
            }, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
        except RuntimeError as err:
            return Response(data={
                'message': err.args[0]
            }, status=status.HTTP_400_BAD_REQUEST)


class TrackTableView(APIView):
    serializer_class = ScanRequestSerializer

    def get(self, request):
        objects = ScanRequest.objects.all()
        return JsonResponse(
            ScanRequestSerializer(objects, many=True).data,
            safe=False
        )


class DashboardView(APIView):

    def get(self, request):
        # Domain
        vul_domain = Vulnerability.objects \
            .annotate(sum=F('info') + F('low') + F('medium') + F('critical')) \
            .values('request', 'request__domain') \
            .annotate(total_count=Sum('sum')) \
            .order_by('-total_count') \
            .first()

        if vul_domain is None:
            domain = 'Not scanned'
        else:
            domain = vul_domain['request__domain']

        # Subdomain
        vul_subdomain = Vulnerability.objects \
            .annotate(sum=F('info') + F('low') + F('medium') + F('critical')) \
            .values('sum', 'subdomain') \
            .order_by('-sum') \
            .first()

        if vul_subdomain is None:
            subdomain = 'Not scanned'
        else:
            subdomain = vul_subdomain['subdomain']

        # Port
        openport = OpenPort.objects \
            .values('port') \
            .annotate(count=Count('port')) \
            .order_by('-count') \
            .first()

        if openport is None:
            port = 'Not scanned'
        else:
            port = openport['port']

        # Vulnerabilities agg
        vulnerabilities = Vulnerability.objects \
            .aggregate(info=Sum('info'), low=Sum('low'), medium=Sum('medium'), critical=Sum('critical'))

        # Port agg
        ports = {}
        portList = OpenPort.objects \
            .values('port') \
            .annotate(count=Count('*'))
        for p in portList:
            ports.setdefault(p['port'], p['count'])

        results = {
            'domain': domain,
            'subdomain': subdomain,
            'port': port,
            'vulnerabilities': vulnerabilities,
            'ports': ports
        }
        return Response(data=results, status=status.HTTP_200_OK)
