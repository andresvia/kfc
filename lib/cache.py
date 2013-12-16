# -*- coding: utf-8 -*-
# clases

from __future__ import print_function
from __future__ import division
from __future__ import absolute_import

import pickle
import os
import time


class CacheObject(object):

    def __init__(self, content):
        self.last_used = time.time()
        self.content = content
        self.create_time = time.time()


class Cache(object):

    def __init__(self, cache_path_db, cache_size, cache_max_age):
        self.dict = None
        self.cache_path_db = cache_path_db
        if os.path.isfile(cache_path_db):
            self.dict = pickle.load(open(cache_path_db, 'rb')) or {}
        else:
            self.dict = {}
        self.size = cache_size
        self.max_size = self.size * 1.5
        self.max_age = cache_max_age

    def cache_get(self, key):
        self.cache_validate()
        if key in self.dict:
            self.dict[key].last_used = time.time()
            return self.dict[key]
        else:
            return None

    def cache_put(self, key, content):
        self.cache_validate()
        if key not in self.dict:
            self.dict[key] = CacheObject(content)
            return True
        else:
            return False

    def cache_validate(self):
        if len(self.dict) > self.max_size:
            first_pass = True
            while len(self.dict) > self.size:
                k_removed = self.remove_less_used()
                if first_pass and k_removed is None:
                    print("ERROR: Algo no esta bien, saliendo del ciclo")
                    break
                first_pass = False
        purgue_time = time.time()
        purgue_k = []
        for k in self.dict:
            if (purgue_time - self.dict[k].create_time > self.max_age or
                purgue_time - self.dict[k].create_time < 0):
                purgue_k.append(k)
        for k in purgue_k:
            self.dict.pop(k)

    def remove_less_used(self):
        time_less_used = time.time()
        k_remove = None
        for k in self.dict:
            if self.dict[k].last_used < time_less_used:
                k_remove = k
                time_less_used = self.dict[k].last_used
        if k_remove in self.dict:
            self.dict.pop(k_remove)
        return k_remove

    def save(self):
        if self.dict is not None:
            pickle.dump(self.dict, open(self.cache_path_db, 'wb'))
