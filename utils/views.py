from django.http import JsonResponse


def handle_404(request, exception):
    response = JsonResponse(
        {"status": "fail", "message": "We can't find the endpoint you are looking for.", })
    response.status_code = 404
    return response


def handle_500(request):
    response = JsonResponse(
        {
            "status": "fail",
            "message": "Internal Server Error Occurred",
        })
    response.status_code = 500
    return response
