from rest_framework import generics
from errata.request_dispatchers.advisory import validate_batch_advisory_get, route_batch_advisory_get
from rest_framework.response import Response


class BatchAdvisory(generics.ListAPIView):

    def get(self, request, *args, **kwargs):

        validation_status, result = validate_batch_advisory_get(request)

        if validation_status:
            response = route_batch_advisory_get(result)
            return Response(data=response)
        else:
            return Response(data=result)
