"""인기 PyPI 패키지 정적 목록 (이름 유사도 비교용, 요약본).

정확도를 높이려면 top-pypi-packages(https://hugovk.github.io/top-pypi-packages/) 등으로 교체하고
`veripi check --popular-file popular.txt` 로 지정하세요.
"""
POPULAR_RAW = """
requests numpy pandas boto3 botocore urllib3 setuptools pip wheel certifi idna charset-normalizer
typing-extensions python-dateutil six s3transfer pyyaml packaging cryptography cffi pycparser pytz attrs
jmespath rsa pyasn1 click jinja2 markupsafe werkzeug flask django fastapi pydantic uvicorn starlette
sqlalchemy psycopg2 psycopg2-binary pymysql mysql-connector-python redis celery pytest pytest-cov
pytest-mock tox black flake8 pylint mypy isort scipy matplotlib seaborn scikit-learn tensorflow torch
torchvision keras transformers tqdm pillow opencv-python beautifulsoup4 lxml selenium scrapy aiohttp httpx
requests-oauthlib oauthlib google-auth google-api-core googleapis-common-protos protobuf grpcio openpyxl
xlrd xlsxwriter pyarrow joblib sympy networkx nltk spacy gensim openai anthropic langchain numba cython
gunicorn docker paramiko pyopenssl pyjwt python-dotenv pexpect colorama rich tabulate toml tomli
jsonschema simplejson ujson orjson regex decorator wrapt platformdirs filelock virtualenv pipenv poetry
twine ipython jupyter notebook ipykernel sphinx markdown pygments docutils mock coverage pluggy iniconfig
zipp importlib-metadata more-itertools azure-core azure-storage-blob google-cloud-storage awscli pymongo
motor elasticsearch kafka-python pika websockets websocket-client python-multipart email-validator
greenlet gevent tornado sanic bottle pyserial psutil pycryptodome pynacl bcrypt passlib tzlocal
babel pyparsing cachetools soupsieve tenacity structlog loguru httplib2 uritemplate proto-plus
sentry-sdk pydantic-core annotated-types anyio sniffio h11 httpcore exceptiongroup
"""
POPULAR = sorted(set(POPULAR_RAW.split()))
