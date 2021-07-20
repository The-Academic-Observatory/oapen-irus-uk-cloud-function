# Copyright 2020 Curtin University
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Author: Aniek Roelofs

import os
import pathlib
import subprocess
import unittest
import uuid
from subprocess import Popen
from types import SimpleNamespace
from unittest.mock import Mock, patch

import geoip2.database
import httpretty
from click.testing import CliRunner
from geoip2.errors import AddressNotFoundError
from google.cloud import storage

import tests.fixtures
from main import (download, download_access_stats_new, download_access_stats_old, download_geoip,
                  list_to_jsonl_gz, replace_ip_address, upload_file_to_storage_bucket)


class TestCloudFunction(unittest.TestCase):

    def __init__(self, *args, **kwargs):
        """ Constructor which sets up variables used by tests.

        :param args: arguments.
        :param kwargs: keyword arguments.
        """

        super(TestCloudFunction, self).__init__(*args, **kwargs)

        self.download_path_v4_country = test_fixtures_path('download_country_2020_03.tsv')
        self.download_path_v4_ip = test_fixtures_path('download_ip_2020_03.tsv')
        self.download_hash_v4 = 'bce685e9'

        self.download_path_v5_base = test_fixtures_path('download_base_2020_04.json')
        self.download_path_v5_base_error = test_fixtures_path('download_base_error_2020_04.json')
        self.download_path_v5_country = test_fixtures_path('download_country_2020_04.json')
        self.download_path_v5_ip = test_fixtures_path('download_ip_2020_04.json')
        self.download_hash_v5 = 'f1f82c14'

    @patch('main.download_geoip')
    @patch('main.geoip2.database.Reader')
    @patch('main.download_access_stats_new')
    @patch('main.download_access_stats_old')
    @patch('main.upload_file_to_storage_bucket')
    def test_download(self, mock_upload_blob, mock_download_old, mock_download_new, mock_geoip_reader,
                      mock_download_geoip):
        """ Test downloading OAPEN Irus UK access stats """
        # download older version
        mock_upload_blob.return_value = True
        mock_download_old.return_value = None
        mock_download_new.return_value = None
        mock_geoip_reader.return_value = 'geoip_client'
        mock_download_geoip.return_value = None

        data = {'release_date': '2020-03',
                'username': 'username',
                'password': 'password',
                'geoip_license_key': 'geoip_license_key',
                'publisher_name': 'publisher_name',
                'publisher_uuid': 'publisher_uuid',
                'bucket_name': 'bucket_name',
                'blob_name': 'blob_name'}
        request = Mock(get_json=Mock(return_value=data), args=data)
        download(request)
        # assert mocked functions are called correctly
        mock_upload_blob.assert_called_once_with('/tmp/oapen_access_stats.jsonl.gz', data['bucket_name'],
                                                 data['blob_name'])
        mock_download_old.assert_called_once_with('/tmp/oapen_access_stats.jsonl.gz', data['release_date'],
                                                  data['username'], data['password'], data['publisher_name'],
                                                  'geoip_client')
        mock_download_new.assert_not_called()
        mock_geoip_reader.assert_called_once_with('/tmp/geolite_city.mmdb')
        mock_download_geoip.assert_called_once_with(data['geoip_license_key'], '/tmp/geolite_city.tar.gz',
                                                    '/tmp/geolite_city.mmdb')

        # download newer version
        mock_upload_blob.reset_mock()
        mock_download_old.reset_mock()
        mock_download_new.reset_mock()
        mock_geoip_reader.reset_mock()
        mock_download_geoip.reset_mock()

        data['release_date'] = '2020-04'
        download(request)
        # assert mocked functions are called correctly
        mock_upload_blob.assert_called_once_with('/tmp/oapen_access_stats.jsonl.gz', data['bucket_name'],
                                                 data['blob_name'])
        mock_download_old.assert_not_called()
        mock_download_new.assert_called_once_with('/tmp/oapen_access_stats.jsonl.gz', data['release_date'],
                                                  data['username'], data['password'], data['publisher_uuid'],
                                                  'geoip_client')
        mock_geoip_reader.assert_called_once_with('/tmp/geolite_city.mmdb')
        mock_download_geoip.assert_called_once_with(data['geoip_license_key'], '/tmp/geolite_city.tar.gz',
                                                    '/tmp/geolite_city.mmdb')

        # test runtime error in case of unsuccessful upload to bucket
        mock_upload_blob.return_value = False
        with self.assertRaises(RuntimeError):
            download(request)

    def test_download_geoip(self):
        """ Test downloading geolite database """
        geoip_license_key = 'license_key'
        url = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=' \
              f'{geoip_license_key}&suffix=tar.gz'
        download_path = 'geolite_city.tar.gz'
        extract_path = 'geolite_city.mmdb'
        with CliRunner().isolated_filesystem():
            with httpretty.enabled():
                httpretty.register_uri(httpretty.GET, uri=url, body='success', content_type="application/gzip")
                # empty files are used, so will raise error
                with self.assertRaises(RuntimeError):
                    download_geoip(geoip_license_key, download_path, extract_path)
            self.assertTrue(os.path.isfile(download_path))
            self.assertTrue(os.path.isfile(extract_path))

    @patch('main.replace_ip_address')
    def test_download_access_stats_old(self, mock_replace_ip):
        """ Test downloading access stats before April 2020 """
        mock_replace_ip.return_value = ('23.1194', '-82.392', 'Suva', 'Peru', 'PE')
        # Test with and without publisher name
        for publisher_name in ['', 'publisher%20name']:
            with CliRunner().isolated_filesystem():
                file_path = 'oapen_access_stats.jsonl.gz'
                release_date = '2020-03'
                start_date = release_date + "-01"
                end_date = release_date + "-31"

                ip_url = f'https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/br1b/?frmRepository=1%7COAPEN+Library' \
                         f'&frmFrom={start_date}&frmTo={end_date}&frmFormat=TSV&Go=Generate+Report'
                country_url = f'https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/br1bCountry/?frmRepository=1%7COAPEN+Library' \
                              f'&frmoapenid=&frmFrom={start_date}&frmTo={end_date}&frmFormat=TSV' \
                              f'&Go=Generate+Report'
                if publisher_name:
                    ip_url += f'&frmPublisher={publisher_name}'
                    country_url += f'&frmPublisher={publisher_name}'

                with httpretty.enabled():
                    # register login page
                    httpretty.register_uri(httpretty.POST,
                                           uri='https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/?action=login',
                                           body='After you have finished your session please remember to')
                    # register ip report
                    with open(self.download_path_v4_ip, 'rb') as f:
                        body = f.read()
                    httpretty.register_uri(httpretty.GET, uri=ip_url, body=body)

                    # register country report
                    with open(self.download_path_v4_country, 'rb') as f:
                        body = f.read()
                    httpretty.register_uri(httpretty.GET, uri=country_url, body=body)

                    # download access stats
                    download_access_stats_old(file_path, release_date, 'username', 'password', publisher_name,
                                              Mock(spec=geoip2.database.Reader))
                    actual_hash = gzip_file_crc(file_path)
                    self.assertEqual(self.download_hash_v4, actual_hash)

                    # Test response status that is not 200
                    httpretty.register_uri(httpretty.GET, uri=ip_url, status=400)
                    with self.assertRaises(RuntimeError):
                        download_access_stats_old(file_path, release_date, 'username', 'password', publisher_name,
                                                  Mock(spec=geoip2.database.Reader))

                # Test response status that is not 200 for login
                with httpretty.enabled():
                    httpretty.register_uri(httpretty.POST,
                                           uri='https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/?action=login',
                                           status=400)
                    with self.assertRaises(RuntimeError):
                        download_access_stats_old(file_path, release_date, 'username', 'password', publisher_name,
                                                  Mock(spec=geoip2.database.Reader))

    @patch('main.replace_ip_address')
    def test_download_access_stats_new(self, mock_replace_ip):
        """ Test downloading access stats since April 2020 """

        mock_replace_ip.return_value = ('23.1194', '-82.392', 'Suva', 'Peru', 'PE')
        # Test with and without publisher_uuid
        for publisher_uuid in ['', 'publisher_uuid']:
            with CliRunner().isolated_filesystem():
                file_path = 'oapen_access_stats.jsonl.gz'
                release_date = '2020-04'
                requestor_id = 'requestor_id'
                api_key = 'api_key'
                base_url = f'https://irus.jisc.ac.uk/api/oapen/reports/oapen_ir/?requestor_id={requestor_id}' \
                           f'&begin_date={release_date}&end_date={release_date}&api_key={api_key}'
                if publisher_uuid:
                    base_url += f'&publisher={publisher_uuid}'

                # Test response with header displaying error & without
                for base_url_path in [self.download_path_v5_base, self.download_path_v5_base_error]:
                    with httpretty.enabled():
                        # register base url
                        with open(base_url_path, 'rb') as f:
                            body = f.read()
                        httpretty.register_uri(httpretty.GET,
                                               uri=base_url,
                                               body=body,
                                               match_querystring=True)
                        # register country url
                        with open(self.download_path_v5_country, 'rb') as f:
                            body = f.read()
                        url_country = base_url + '&attributes_to_show=Country'
                        httpretty.register_uri(httpretty.GET,
                                               uri=url_country,
                                               body=body,
                                               match_querystring=True)
                        # register ip url
                        with open(self.download_path_v5_ip, 'rb') as f:
                            body = f.read()
                        url_ip = base_url + '&attributes_to_show=Client_IP'
                        httpretty.register_uri(httpretty.GET,
                                               uri=url_ip,
                                               body=body,
                                               match_querystring=True)

                        # test response without error in header
                        if base_url_path == self.download_path_v5_base:
                            download_access_stats_new(file_path, release_date, requestor_id, api_key, publisher_uuid,
                                                      Mock(spec=geoip2.database.Reader))

                            actual_hash = gzip_file_crc(file_path)
                            self.assertEqual(self.download_hash_v5, actual_hash)
                        # test response with error in header
                        else:
                            with self.assertRaises(RuntimeError):
                                download_access_stats_new(file_path, release_date, requestor_id, api_key,
                                                          publisher_uuid, Mock(spec=geoip2.database.Reader))

                # Test response status that is not 200
                with httpretty.enabled():
                    httpretty.register_uri(httpretty.GET,
                                           uri=base_url,
                                           status=400)
                    with self.assertRaises(RuntimeError):
                        download_access_stats_new(file_path, release_date, requestor_id, api_key, publisher_uuid,
                                                  Mock(spec=geoip2.database.Reader))

    def test_replace_ip_address(self):
        """ Test replacing ip address with geographical information mocking the geolite database """
        latitude = '23.1194',
        longitude = '-82.392',
        city = 'Suva',
        country = 'Peru',
        country_iso_code = 'PE'

        geoip_client = Mock(spec=geoip2.database.Reader)
        geoip_client.city.return_value = SimpleNamespace(location=SimpleNamespace(latitude=latitude,
                                                                                  longitude=longitude),
                                                         city=SimpleNamespace(name=city),
                                                         country=SimpleNamespace(name=country,
                                                                                 iso_code=country_iso_code))
        client_lat, client_lon, client_city, client_country, client_country_code = replace_ip_address('100.229.139.139',
                                                                                                      geoip_client)

        self.assertEqual(latitude, client_lat)
        self.assertEqual(longitude, client_lon)
        self.assertEqual(city, client_city)
        self.assertEqual(country, client_country)
        self.assertEqual(country_iso_code, client_country_code)

        # Test AddressNotFoundError
        geoip_client.city.side_effect = AddressNotFoundError()
        client_lat, client_lon, client_city, client_country, client_country_code = replace_ip_address('72.59.232.155',
                                                                                                      geoip_client)
        self.assertEqual('', client_lat)
        self.assertEqual('', client_lon)
        self.assertEqual('', client_city)
        self.assertEqual('', client_country)
        self.assertEqual('', client_country_code)

    def test_list_to_jsonl_gz(self):
        """ Test writing list of dicts to jsonl.gz file """
        list_of_dicts = [{'k1a': 'v1a', 'k2a': 'v2a'},
                         {'k1b': 'v1b', 'k2b': 'v2b'}
                         ]
        file_path = 'list.jsonl.gz'
        expected_file_hash = 'e608cfeb'
        with CliRunner().isolated_filesystem():
            list_to_jsonl_gz(file_path, list_of_dicts)
            self.assertTrue(os.path.isfile(file_path))
            actual_file_hash = gzip_file_crc(file_path)
            self.assertEqual(expected_file_hash, actual_file_hash)

    def test_upload_file_to_storage_bucket(self):
        """ Test that file is uploaded to storage bucket """
        runner = CliRunner()
        with runner.isolated_filesystem():
            # Create file
            upload_file_name = f'{random_id()}.txt'
            with open(upload_file_name, 'w') as f:
                f.write('hello world')
            expected_crc32c = 'yZRlqg=='

            # Create client for blob
            gc_bucket_name: str = os.getenv('TEST_GCP_BUCKET_NAME')
            blob_name = upload_file_name
            storage_client = storage.Client()
            bucket = storage_client.get_bucket(gc_bucket_name)
            blob = bucket.blob(blob_name)

            try:
                success = upload_file_to_storage_bucket(upload_file_name, gc_bucket_name, blob_name)
                self.assertTrue(success)
                self.assertTrue(blob.exists())
                blob.reload()
                self.assertEqual(expected_crc32c, blob.crc32c)

            finally:
                if blob.exists():
                    blob.delete()


def test_fixtures_path(file_name: str):
    """ Get fixtures path.

    :param file_name: File name of the test fixture file.
    :return: Full path to test fixture file.
    """
    module_path = pathlib.Path(tests.fixtures.__file__).resolve()
    base_path = os.path.dirname(module_path)
    return os.path.join(base_path, file_name)


def random_id():
    """ Generate a random id for bucket name.

    :return: a random string id.
    """
    return str(uuid.uuid4()).replace("-", "")


def gzip_file_crc(file_path: str) -> str:
    """ Get the crc of a gzip file.

    :param file_path: the path to the file.
    :return: the crc.
    """

    proc: Popen = subprocess.Popen(['gzip', '-vl', file_path], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    output, error = proc.communicate()
    output = output.decode('utf-8')
    return output.splitlines()[1].split(' ')[1].strip()
