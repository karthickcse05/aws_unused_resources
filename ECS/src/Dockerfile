FROM python:3


COPY requirements.txt /aws-unused/
RUN pip3 install -r /aws-unused/requirements.txt

COPY  *.py /aws-unused/
RUN chmod +x /aws-unused/aws_resources.py

CMD  ["python", "/aws-unused/aws_resources.py" ]