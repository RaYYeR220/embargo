# The desk's agents. One image, one agent per container, chosen by $DESK_AGENT.
FROM python:3.12-slim

WORKDIR /app
COPY desk/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# The code and the public corpus the verifier grounds against.
COPY desk/ ./desk/
COPY sandbox/ ./sandbox/
COPY bench/corpus/ ./bench/corpus/

# DESK_AGENT selects which agent this container runs: intake | reproducer | disclosure
ENV DESK_AGENT=intake
CMD ["sh", "-c", "python -m desk.agents.$DESK_AGENT"]
