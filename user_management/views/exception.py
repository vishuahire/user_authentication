from rest_framework.generics import *
from user_management.models.exception import ExceptionError
from user_management.serializers.exception import ExceptionErrorSerializer
from rest_framework.response import Response
from rest_framework import status


class ExceptionErrrosView(CreateAPIView):
    """
    Throw exception

    passing parameter- none

    return response 
    """
    queryset = ExceptionError.objects.all()
    serializer_class = ExceptionErrorSerializer


    def create(self, request, *args, **kwargs):
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            self.perform_create(serializer)
            headers = self.get_success_headers(serializer.data)
            response = {'status': "success",'message':serializer.data,status:status.HTTP_201_CREATED}
            return Response(response,  headers=headers)
        else:
            # if data is invalid, returns error message along with status code 
            response = {'status': "error",'message':serializer.errors,'status_code':status.HTTP_400_BAD_REQUEST}
            return Response(response)

