FROM python:2.7
ADD application.py /
ADD database_setup.py /
ADD populate_items.py /
ADD css css/
ADD static static/
ADD templates templates/
RUN pip install flask
RUN pip install requests
RUN pip install flask_httpauth
RUN pip install passlib
RUN pip install sqlalchemy
RUN pip install oauth2client
RUN python database_setup.py
RUN python populate_items.py
CMD [ "python", "./application.py" ]
EXPOSE 5000