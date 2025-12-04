import os
import subprocess
from logging import getLogger

logger = getLogger("yunohost.utils.database")


# ================================= #
#              Mysql                #
# ================================= #

def _mysql(query: str, **kwargs) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Force output in english
    env["LC_ALL"] = "C"
    query_to_log = query
    if "redact" in kwargs:
        query_to_log = query.replace(kwargs.pop("redact"), "*" * 12)
    logger.debug(f"Running mysql query: {query_to_log}")
    p = subprocess.run("mysql -B", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=query, **kwargs)
    assert p.returncode == 0, f"Uhoh, mysql query {query_to_log} failed !? " + str(p.stdout.decode())
    return p


def mysql_db_exists(db) -> bool:
    return os.system(f'mysqlshow | grep -q "^| {db} "') == 0


def mysql_create_db(db: str, user: str, pwd: str) -> None:
    _mysql(
        f"CREATE DATABASE {db}; "
        f"GRANT ALL PRIVILEGES ON {db}.* TO '{user}'@'localhost' "
        f"IDENTIFIED BY '{pwd}' WITH GRANT OPTION;",
        redact=pwd
    )


def mysql_drop_db(db: str) -> None:
    _mysql(f"DROP DATABASE {db};")


def mysql_dump_db_to_file(db: str, target: str) -> None:
    pass
    # FIXME / TODO

    #local default_character_set=()
    #if [[ -n "$database" ]]; then
    #    default_character_set=(
    #        --default-character-set
    #        "$(mysql -B "$database" <<< 'show variables like "character_set_database";' | tail -n1 | cut -f2)"
    #    )
    #fi

    # mysqldump "${default_character_set[@]}" --single-transaction --skip-dump-date --routines "$database"


def mysql_user_exists(user: str) -> bool:
    return bool(_mysql(f"SELECT User from mysql.user WHERE User = '{user}';").stdout.decode().strip())


def mysql_drop_user(user: str) -> None:
    _mysql(f"DROP USER '{user}'@'localhost';")


# ================================= #
#           Postgresql              #
# ================================= #


def _psql(query: str, **kwargs) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    # Force output in english
    env["LC_ALL"] = "C"
    query_to_log = query
    if "redact" in kwargs:
        query_to_log = query.replace(kwargs.pop("redact"), "*" * 12)
    logger.debug(f"Running psql query: {query_to_log}")
    p = subprocess.run("sudo --login --user=postgres psql -tA", env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, input=query, **kwargs)
    assert p.returncode == 0, f"Uhoh, psql query {query_to_log} failed !? " + str(p.stdout.decode())
    return p


def psql_create_db(db: str, user: str) -> None:
    _psql(
        f"CREATE DATABASE {db}; "
        f"ALTER DATABASE {db} OWNER TO {user}; "
        f"GRANT ALL PRIVILEGES ON DATABASE {db} TO {user} WITH GRANT OPTION;"
    )


def psql_drop_db(db: str) -> None:
    # First, force disconnection of all clients connected to the database
    # https://stackoverflow.com/questions/17449420/postgresql-unable-to-drop-database-because-of-some-auto-connections-to-db
    _psql(f"DROP DATABASE {db} WITH (FORCE);")


def psql_dump_db_to_file(db: str, target: str) -> None:
    pass
    # FIXME / TODO
    # sudo --login --user=postgres pg_dump "$database"


def psql_create_user(user: str, pwd: str) -> None:
    _psql(f"CREATE USER {user} WITH ENCRYPTED PASSWORD '{pwd}';", redact=pwd)


def psql_drop_user(user: str) -> None:
    _psql(f"DROP USER {user};")


def psql_user_exists(user: str) -> bool:
    return bool(_psql(f"SELECT rolname FROM pg_roles WHERE rolname='{user}';").stdout.decode().strip())


def psql_db_exists(db: str) -> bool:
    return bool(_psql(f"SELECT datname FROM pg_database WHERE datname='{db}';").stdout.decode().strip())
