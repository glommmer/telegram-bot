import os
import pickle
import logging
import configparser
from redis import StrictRedis
from redis.sentinel import Sentinel
from collections.abc import MutableMapping
from telegram_bot.ext import ConversationHandler


# Read configuration file
current_dir = os.path.dirname(os.path.abspath(__file__))
ini_path = os.path.join(current_dir, "env/telegram_bot.ini")
config = configparser.ConfigParser()
config.read(ini_path)

# Load environment variables
service_name = config["SENTINEL"]["SERVICE_NAME"]
service_password = config["SENTINEL"]["SERVICE_PASSWORD"]

# Redis-Sentinel settings
sentinel = Sentinel([("localhost", 26379)], socket_timeout=0.1)
master = sentinel.master_for(
    service_name, socket_timeout=0.1, password=service_password
)
slave = sentinel.slave_for(service_name, socket_timeout=0.1, password=service_password)


class RedisConversationStore(MutableMapping):
    def __init__(self, redis_client):
        self.redis_client = redis_client

    def __getitem__(self, key):
        # Redis에서 값을 가져오고 역직렬화(pickle)를 통해 복원
        value = self.redis_client.get(self._serialize_key(key))
        if value is None:
            raise KeyError(key)
        return pickle.loads(value)

    def __setitem__(self, key, value):
        # 값을 직렬화(pickle)하여 Redis에 저장
        self.redis_client.set(self._serialize_key(key), pickle.dumps(value))

    def __delitem__(self, key):
        # Redis에서 해당 키 삭제
        if not self.redis_client.delete(self._serialize_key(key)):
            raise KeyError(key)

    def __iter__(self):
        # Redis에 저장된 모든 키를 반환
        return iter(self.redis_client.keys())

    def __len__(self):
        # Redis에 저장된 키의 개수를 반환
        return len(self.redis_client.keys())

    @classmethod
    def _serialize_key(cls, key):
        # ConversationKey를 직렬화하는 함수 (필요에 따라 맞춤 설정 가능)
        return str(key)


class RedisConversationHandler(ConversationHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._conversations = RedisConversationStore(master)


class RedisActions:
    def __init__(self):
        pass

    @classmethod
    def set_to_redis(cls, user_id, key, value):
        logging.debug(f"## master: set_to_redis: {user_id}/{key}/{value}")
        master.set(f"user_data:{user_id}:{key}", value)

    @classmethod
    def get_from_redis(cls, user_id, key):
        value = None
        try:
            logging.debug(f"## slave: get_from_redis: {user_id}/{key}")
            value = slave.get(f"user_data:{user_id}:{key}")
        except Exception as e:
            logging.error(e)
            logging.debug(f"## master: get_from_redis: {user_id}/{key}")
            value = master.get(f"user_data:{user_id}:{key}")
        finally:
            if value:
                return value.decode("utf-8")
            else:
                return None

    @classmethod
    def delete_from_redis(cls, user_id, key):
        logging.debug(f"## master: delete_from_redis: {user_id}/{key}")
        master.delete(f"user_data:{user_id}:{key}")

    @classmethod
    def append_to_redis(cls, user_id, key, *args):
        logging.debug(f"## master: append_to_redis: {user_id}/{key}/{args}")
        master.rpush(f"user_data:{user_id}:{key}", *args)

    @classmethod
    def set_list_to_redis(cls, user_id, key, *args):
        logging.debug(f"## master: set_list_to_redis: {user_id}/{key}/{args}")
        cls.delete_from_redis(user_id, key)
        cls.append_to_redis(user_id, key, *args)

    @classmethod
    def get_list_from_redis(cls, user_id, key, sta_idx=0, end_idx=-1):
        values = []
        try:
            logging.debug(f"## slave: get_list_from_redis: {user_id}/{key}")
            values = slave.lrange(f"user_data:{user_id}:{key}", sta_idx, end_idx)
        except Exception as e:
            logging.error(e)
            logging.debug(f"## master: get_list_from_redis: {user_id}/{key}")
            values = master.lrange(f"user_data:{user_id}:{key}", sta_idx, end_idx)
        finally:
            if values:
                return list(map(lambda x: x.decode("utf-8"), values))
            else:
                return None

    @classmethod
    def sync_users_to_redis(cls, user_ids):
        logging.debug(f"## sync_users_to_redis")
        master.delete("allowed_users")
        if user_ids:
            master.sadd("allowed_users", *user_ids)

    @classmethod
    def add_user_to_redis(cls, user_id):
        logging.debug(f"## add_user_to_redis")
        master.sadd("allowed_users", user_id)

    @classmethod
    def is_user_allowed_in_redis(cls, user_id):
        try:
            logging.debug(f"## slave: is_user_allowed: {user_id}")
            return slave.sismember("allowed_users", user_id)
        except Exception as e:
            logging.error(e)
            logging.debug(f"## master: is_user_allowed: {user_id}")
            return master.sismember("allowed_users", user_id)
