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

import calendar
import csv
import gzip
import io
import logging
import re
import shutil
import subprocess
from datetime import datetime
from typing import List, Tuple, Union

import geoip2.database
import jsonlines
import requests
from bs4 import BeautifulSoup
from geoip2.errors import AddressNotFoundError
from google.cloud import storage
from requests import Session


def download(request):
    """ Download oapen irus uk access stats data, replace IP addresses and upload data to storage bucket.

    :param request: (flask.Request): HTTP request object.
    :return: None.
    """

    request_json = request.get_json()
    release_date = request_json.get('release_date')  # 'YYYY-MM'
    username = request_json.get('username')
    password = request_json.get('password')
    geoip_license_key = request_json.get('geoip_license_key')
    publisher_name = request_json.get('publisher_name')  # e.g. 'UCL+Press'
    publisher_uuid = request_json.get('publisher_uuid')  # e.g. 'df73bf94-b818-494c-a8dd-6775b0573bc2'
    bucket_name = request_json.get('bucket_name')
    blob_name = request_json.get('blob_name')

    # download geoip database
    download_geoip(geoip_license_key, '/tmp/geolite_city.tar.gz', '/tmp/geolite_city.mmdb')

    # initialise geoip client
    geoip_client = geoip2.database.Reader('/tmp/geolite_city.mmdb')

    # download oapen access stats and replace ip addresses
    file_path = '/tmp/oapen_access_stats.jsonl.gz'
    logging.info(f'Downloading oapen access stats for month: {release_date}, publisher name: {publisher_name}, '
                 f'publisher UUID: {publisher_uuid}')
    if datetime.strptime(release_date, '%Y-%m') >= datetime(2020, 4, 1):
        download_access_stats_new(file_path, release_date, username, password, publisher_uuid, geoip_client)
    else:
        download_access_stats_old(file_path, release_date, username, password, publisher_name, geoip_client)

    # upload oapen access stats to bucket
    success = upload_file_to_storage_bucket(file_path, bucket_name, blob_name)
    if not success:
        raise RuntimeError('Uploading file to storage bucket unsuccessful')


def download_geoip(geoip_license_key: str, download_path: str, extract_path: str):
    """ Download geoip database. The database is downloaded as a .tar.gz file and extracted to a '.mmdb' file.

    :param geoip_license_key: The geoip license key
    :param download_path: The download path of .tar.gz file
    :param extract_path: The extract path of .mmdb file
    :return: None.
    """
    geolite_url = 'https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-City&license_key=' \
                  f'{geoip_license_key}&suffix=tar.gz'

    # Download release in tar.gz format
    logging.info(f'Downloading geolite database file to: {download_path}')
    with requests.get(geolite_url, stream=True) as response:
        with open(download_path, 'wb') as file:
            shutil.copyfileobj(response.raw, file)

    # Tar file contains multiple files, use tar -ztf to get path of 'GeoLite2-City.mmdb'
    # Use this path to extract only GeoLite2-City.mmdb to a new file.
    logging.info(f'Extracting geolite database file to: {extract_path}')
    cmd = f"registry_path=$(tar -ztf {download_path} | grep -m1 '/GeoLite2-City.mmdb'); " \
          f"tar -xOzf {download_path} $registry_path > {extract_path}"
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, executable='/bin/bash')
    output, error = proc.communicate()
    logging.info(f"stdout: {output}")
    logging.info(f"stderr: {error}")
    if proc.returncode != 0:
        raise RuntimeError('Extracting geolite database unsuccessful')


def download_access_stats_old(file_path: str, release_date: str, username: str, password: str, publisher_name: str,
                              geoip_client: geoip2.database.Reader):
    """ Download the oapen irus uk access stats data and replace IP addresses with geographical information.
    Data is downloaded from both BR1b IP and BR1b Country reports, these are COUNTER 4 reports. The results for each
    book from both reports are merged into one result dictionary.

    :param file_path: Path to store the access stats results.
    :param release_date: Release date ('YYYY-MM')
    :param username: OAPEN username/email
    :param password: OAPEN password
    :param publisher_name: Publisher name
    :param geoip_client: Geoip client
    :return: None
    """
    # get last date of month
    year, month = release_date.split('-')
    last_date_month = str(calendar.monthrange(int(year), int(month))[1])

    start_date = release_date + "-01"
    end_date = release_date + "-" + last_date_month
    ip_url = f'https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/br1b/?frmRepository=1%7COAPEN+Library' \
             f'&frmFrom={start_date}&frmTo={end_date}&frmFormat=TSV&Go=Generate+Report'
    country_url = f'https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/br1bCountry/?frmRepository=1%7COAPEN+Library' \
                  f'&frmoapenid=&frmFrom={start_date}&frmTo={end_date}&frmFormat=TSV' \
                  f'&Go=Generate+Report'

    # start a requests session
    session = requests.Session()

    # login
    login_response = session.post('https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/?action=login', data={
        'email': username,
        'password': password,
        'action': 'login'
    })
    if 'After you have finished your session please remember to' in login_response.text:
        logging.info('Successfully logged in at https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/?action=login')
    else:
        raise RuntimeError(f'Login at https://irus.jisc.ac.uk/IRUSConsult/irus-oapen/v2/?action=login unsuccessful')

    # Get list of all publisher names
    if publisher_name:
        publishers = [publisher_name]
    else:
        publishers = list_all_publishers(ip_url, session)

    all_results = []
    for publisher_name in publishers:
        ip_url += f'&frmPublisher={publisher_name}'
        country_url += f'&frmPublisher={publisher_name}'

        # get tsv files of reports and store results in list of dicts using csv dictreader
        ip_entries, publisher, begin_date, end_date = download_tsv_file(ip_url, session)
        if not ip_entries:
            continue
        country_entries, _, _, _ = download_tsv_file(country_url, session)

        # set values for first book
        book_title = ip_entries[0]['Title']
        grant = ip_entries[0]['Grant']
        grant_number = ip_entries[0]['Grant Number']
        doi = ip_entries[0]['DOI']
        isbn = ip_entries[0]['ISBN'].strip('ISBN ')
        location_info = []
        total_title_requests = 0

        prev_id = None
        # loop through clients in ip_entries
        for entry in ip_entries:
            proprietary_id = entry['Proprietary Identifier']
            # Write out results of previous title when getting to new title
            if prev_id and prev_id != proprietary_id:
                # Get info from all rows of country_entries with the same book id
                country_info, country_title_requests = get_country_info(prev_id, country_entries)
                # Check that the total title requests for 1 book from IP and Country reports are the same
                assert total_title_requests == country_title_requests
                all_results = add_result(prev_id, None, doi, isbn, book_title, grant, grant_number, publisher, begin_date,
                                         end_date, total_title_requests, None, None, None, None, country_info,
                                         location_info, '4', all_results)

                # Get info for new book title
                book_title = entry['Title']
                grant = entry['Grant']
                grant_number = entry['Grant Number']
                doi = entry['DOI']
                isbn = entry['ISBN'].strip('ISBN ')

                # Reset location info and total title requests
                location_info = []
                total_title_requests = 0

            # Get location info
            client_ip = entry['IP Address']
            title_requests = entry['Reporting Period Total']
            add_location_info(location_info, client_ip, geoip_client, title_requests=title_requests)

            # Sum the title requests
            total_title_requests += int(title_requests)

            # Set the previous id
            prev_id = proprietary_id
            continue

        # Add result of the last book title
        country_info, country_title_requests = get_country_info(prev_id, country_entries)
        assert total_title_requests == country_title_requests
        all_results = add_result(prev_id, None, doi, isbn, book_title, grant, grant_number, publisher, begin_date,
                                 end_date, total_title_requests, None, None, None, None, country_info, location_info,
                                 '4', all_results)

    logging.info(f'Found {len(all_results)} access stats entries')
    list_to_jsonl_gz(file_path, all_results)


def download_access_stats_new(file_path: str, release_date: str, username: str, password: str, publisher_uuid: str,
                              geoip_client: geoip2.database.Reader):
    """ Download the oapen irus uk access stats data and replace IP addresses with geographical information.
    The API is queried 3 times. Once without any attributes, once with the country attribute and once with the IP
    attribute. The results of these queries are merged into one result dictionary.

    :param file_path: Path to store the access stats results.
    :param release_date: Release date ('YYYY-MM')
    :param username: OAPEN requestor ID
    :param password: OAPEN API Key
    :param publisher_uuid: UUID of publisher
    :param geoip_client: Geoip client
    :return: None.
    """
    # Create urls
    requestor_id = username
    api_key = password
    base_url = f'https://irus.jisc.ac.uk/api/oapen/reports/oapen_ir/?requestor_id={requestor_id}' \
               f'&begin_date={release_date}&end_date={release_date}&api_key={api_key}'
    if publisher_uuid:
        base_url += f'&publisher={publisher_uuid}'
    url_ip = base_url + '&attributes_to_show=Client_IP'
    url_country = base_url + '&attributes_to_show=Country'

    # Get responses
    base_json = get_response(base_url)
    ip_json = get_response(url_ip)
    country_json = get_response(url_country)

    # Check for any errors/exceptions in response
    for response_json in [base_json, ip_json, country_json]:
        report_header = response_json['Report_Header']
        try:
            exceptions = report_header['Exceptions']
            raise RuntimeError(f'Exceptions found in report header: {exceptions}')
        except KeyError:
            pass

    all_results = []
    # Check that the number of books for each query is the same
    assert len(base_json['Report_Items']) == len(ip_json['Report_Items']) == len(country_json['Report_Items'])

    # Loop through the items of the 3 json objects in parallel
    for base_item, ip_item, country_item in zip(base_json['Report_Items'], ip_json['Report_Items'],
                                                country_json['Report_Items']):
        # Use base item to get general info on book
        book_title = base_item['Item']
        publisher = base_item['Publisher']
        begin_date = base_item['Performance'][0]['Period']['Begin_Date']
        end_date = base_item['Performance'][0]['Period']['End_Date']

        # Get item IDs if they are given
        ids = {'Proprietary': None, 'URI': None, 'DOI': None, 'ISBN': None}
        for id_name in ids:
            try:
                id_value = base_item['Item_ID'][id_name]
                ids[id_name] = id_value
            except KeyError:
                pass
        proprietary_id = ids['Proprietary']
        uri = ids['URI']
        doi = ids['DOI']
        isbn = ids['ISBN']

        # Get location info
        location_info = []
        for client in ip_item['Performance']:
            instance = client['Instance']
            total_item_investigations = instance['Total_Item_Investigations']
            total_item_requests = instance['Total_Item_Requests']
            unique_item_investigations = instance['Unique_Item_Investigations']
            unique_item_requests = instance['Unique_Item_Requests']

            client_ip = client['Instance']['Client_IP']
            add_location_info(location_info, client_ip, geoip_client,
                              total_item_investigations=total_item_investigations,
                              total_item_requests=total_item_requests,
                              unique_item_investigations=unique_item_investigations,
                              unique_item_requests=unique_item_requests)

        # Get country info
        country_info = []
        for country in country_item['Performance']:
            instance = country['Instance']
            country_name = instance.get('Country', {'Country_Name': ''})['Country_Name']
            country_code = instance.get('Country', {'Country_Code': ''})['Country_Code']
            total_item_investigations = instance['Total_Item_Investigations']
            total_item_requests = instance['Total_Item_Requests']
            unique_item_investigations = instance['Unique_Item_Investigations']
            unique_item_requests = instance['Unique_Item_Requests']
            add_country_info(country_info, country_name, country_code,
                             total_item_investigations=total_item_investigations,
                             total_item_requests=total_item_requests,
                             unique_item_investigations=unique_item_investigations,
                             unique_item_requests=unique_item_requests)

        total_item_investigations = 0
        total_item_requests = 0
        unique_item_investigations = 0
        unique_item_requests = 0
        for unknown in base_item['Performance']:
            instance = unknown['Instance']
            total_item_investigations += instance['Total_Item_Investigations']
            total_item_requests += instance['Total_Item_Requests']
            unique_item_investigations += instance['Unique_Item_Investigations']
            unique_item_requests += instance['Unique_Item_Requests']

        all_results = add_result(proprietary_id, uri, doi, isbn, book_title, None, None, publisher, begin_date,
                                 end_date, None, total_item_investigations, total_item_requests,
                                 unique_item_investigations, unique_item_requests, country_info, location_info,
                                 '5', all_results)
    logging.info(f'Found {len(all_results)} access stats entries')
    list_to_jsonl_gz(file_path, all_results)


def list_all_publishers(url: str, session: Session) -> List[str]:
    """

    :param url:
    :param session:
    :return:
    """
    response = session.get(url)
    soup = BeautifulSoup(response.text)
    publishers = [match.text for match in soup.find('select', attrs={'name': 'frmPublisher'}).find_all('option')]
    return publishers


def download_tsv_file(url: str, session: Session) -> [List[dict], str, str, str]:
    """ Download the COUNTER 4 report from an URL to a tsv file, then store the content of the tsv file in a list of
    dictionaries.

    :param url: The URL to the report.
    :param session: The requests session.
    :return: The report entries in a list of dictionaries, publisher name, begin date and end date.
    """
    response = session.get(url)
    if response.status_code == 200 and response.text.startswith('"Book Report 1b (BR1b)"'):
        logging.info(f'Successfully downloaded tsv file from URL: {url}')
    else:
        raise RuntimeError(f'Downloading tsv file unsuccessful from URL: {url}')
    content = response.content.decode('utf-8').splitlines()

    # Get publisher and begin & end date
    publisher = content[1].strip('"')
    begin_date, end_date = content[3].strip('"').split(' to ')

    # Store results in list using csv dictreader. Skip the first lines which contain report info.
    csv_reader = csv.DictReader(content[6:7] + content[8:], delimiter='\t')
    csv_entries = [{k: v for k, v in row.items()} for row in csv_reader]

    return csv_entries, publisher, begin_date, end_date


def get_response(url: str) -> dict:
    """ Get the response from the report URL in json format.

    :param url: The URL to the report.
    :return: Response in JSON format.
    """
    response = requests.get(url)
    masked_url = re.sub(r'requestor_id=[^&]*', 'requestor_id=<requestor_id>',
                        re.sub('api_key=[^&]*', 'api_key=<api_key>', url))
    if response.status_code != 200:
        raise RuntimeError(f'Request unsuccessful, url: {masked_url}, status code: {response.status_code}, '
                           f'response: {response.text}, reason: {response.reason}')
    logging.info(f'Successfully got response from URL: {masked_url}')
    response_json = response.json()
    return response_json


def get_country_info(proprietary_id: str, country_entries: List[dict]) -> [List[dict], int]:
    """ Get country info for all entries with the given proprietary id in the country_entries list.
    After obtaining the country info, the entries are deleted from the list. The list is ordered by id and should
    always start with the proprietary_id.

    :param proprietary_id: The proprietary_id of the book.
    :param country_entries: List with country entries from the country report.
    :return: Country_info list and total title requests based on the country report.
    """
    total_title_requests = 0
    country_info = []
    # Iterate through all country entries, sorted by id
    for i, entry in enumerate(country_entries):
        book_id = entry['Proprietary Identifier']
        # Get info for entries that match proprietary id
        if book_id == proprietary_id:
            country_name = entry['Country']
            title_requests = entry['Reporting Period Total']
            add_country_info(country_info, country_name, '', title_requests=title_requests)

            total_title_requests += int(entry['Reporting Period Total'])
        else:
            # Delete all entries that were iterated through from list and exit loop
            for idx in range(i):
                country_entries.pop(0)
            break
    return country_info, total_title_requests


def add_country_info(country_info: List[dict], country_name: str, country_code: str, title_requests: str = None,
                     total_item_investigations: int = None, total_item_requests: int = None,
                     unique_item_investigations: int = None, unique_item_requests: int = None):
    """ Add items to the country_info list. The country_info list contains dictionaries with country info for 1 book.
    Each dict is a different country and the metrics associated with that country.

    :param country_info: The country info list to which the info of a single country will be added.
    :param country_name: The country name.
    :param country_code: The country code.
    :param title_requests: The number of title requests for that country.
    :param total_item_investigations: The number of total item investigations for that country.
    :param total_item_requests: The number of total item requests for that country.
    :param unique_item_investigations: The number of unique item investigations for that country.
    :param unique_item_requests: The number of unique item requests for that country.
    :return: Nothing. The list is updated in-place.
    """
    country_record = {'name': country_name,
                      'code': country_code,
                      'title_requests': title_requests,
                      'total_item_investigations': total_item_investigations,
                      'total_item_requests': total_item_requests,
                      'unique_item_investigations': unique_item_investigations,
                      'unique_item_requests': unique_item_requests}

    country_info.append(country_record)


def add_location_info(location_info: List[dict], client_ip: str, geoip_client: geoip2.database.Reader,
                      title_requests: str = None, total_item_investigations: int = None,
                      total_item_requests: int = None, unique_item_investigations: int = None,
                      unique_item_requests: int = None):
    """ Add items to the location_info list. The location_info list contains dictionaries with location info for 1
    book, obtained from the IP address. Each dict is a client with unique location info and the metrics associated
    with that client.

    :param location_info: The location info list to which the location info of a client will be added.
    :param client_ip: The IP address of the client.
    :param geoip_client: The geoip client, used to replace IP address.
    :param title_requests: The number of title requests for that location.
    :param total_item_investigations: The number of total item investigations for that location.
    :param total_item_requests: The number of total item requests for that location.
    :param unique_item_investigations: The number of unique item investigations for that location.
    :param unique_item_requests: The number of unique item requests for that location.
    :return: Nothing. The list is updated in-place.
    :return:
    """
    client_lat, client_lon, client_city, client_country, client_country_code = replace_ip_address(client_ip,
                                                                                                  geoip_client)
    location_record = {'latitude': client_lat,
                       'longitude': client_lon,
                       'city': client_city,
                       'country_name': client_country,
                       'country_code': client_country_code,
                       'title_requests': title_requests,
                       'total_item_investigations': total_item_investigations,
                       'total_item_requests': total_item_requests,
                       'unique_item_investigations': unique_item_investigations,
                       'unique_item_requests': unique_item_requests}

    location_info.append(location_record)


def add_result(proprietary_id: str, uri: [str, None], doi: str, isbn: str, book_title: str,
               grant: [str, None], grant_number: [str, None], publisher: str, begin_date: str, end_date: str,
               total_title_requests: [int, None], total_item_investigations: [int, None],
               total_item_requests: [int, None], unique_item_investigations: [int, None],
               unique_item_requests: [int, None], country_info: List[dict], location_info: List[dict],
               version_info: str, all_results: List[dict]) -> list:
    """ Create a single dictionary with all the metadata and measured metrics for a single book. This is then added
    to a list which contains dictionaries for all books.

    :param proprietary_id: Proprietary identifier of the book.
    :param uri: URI of the book. Only available for data since 2020-04-01.
    :param doi: DOI of the book.
    :param isbn: ISBN of the book.
    :param book_title: Title of the book.
    :param grant: Grant. Only available for data before 2020-04-01.
    :param grant_number: Grant number. Only available for data before 2020-04-01.
    :param publisher: The publisher.
    :param begin_date: The begin date of the investigated period.
    :param end_date: The end date of the investigated period.
    :param total_title_requests: The total number of title requests. Only available for data before 2020-04-01.
    :param total_item_investigations: The total number of item investigations. Only available for data since 2020-04-01.
    :param total_item_requests: The total number of item requests. Only available for data since 2020-04-01.
    :param unique_item_investigations: The number of unique item investigations. Only available for data since
    2020-04-01.
    :param unique_item_requests: The number of unique item requests. Only available for data since 2020-04-01.
    :param country_info: List with stats on the country level.
    :param location_info: List with stats on the location level.
    :param version_info: The version info, corresponding to the COUNTER report type (4 or 5).
    :param all_results: List with all results dictionaries
    :return: The list with all results dictionaries
    """
    result = {
        'proprietary_id': proprietary_id,
        'URI': uri,
        'DOI': doi,
        'ISBN': isbn,
        'book_title': book_title,
        'grant': grant,
        'grant_number': grant_number,
        'publisher': publisher,
        'begin_date': begin_date,
        'end_date': end_date,
        'title_requests': total_title_requests,
        'total_item_investigations': total_item_investigations,
        'total_item_requests': total_item_requests,
        'unique_item_investigations': unique_item_investigations,
        'unique_item_requests': unique_item_requests,
        'country': country_info,
        'locations': location_info,
        'version': version_info
    }
    result = {k: None if not v else v for k, v in result.items()}
    all_results.append(result)
    return all_results


def replace_ip_address(client_ip: str, geoip_client: geoip2.database.Reader) -> \
        Tuple[Union[float, str], Union[float, str], str, str, str]:
    """ Replace IP addresses with geographical information using the geoip client.

    :param client_ip: Ip address of the client that is using oapen irus uk
    :param geoip_client: The geoip client
    :return: latitude, longitude, city, country and country_code of the client.
    """
    try:
        geoip_response = geoip_client.city(client_ip)
    except AddressNotFoundError:
        return '', '', '', '', ''

    client_lat = geoip_response.location.latitude
    client_lon = geoip_response.location.longitude
    client_city = geoip_response.city.name
    client_country = geoip_response.country.name
    client_country_code = geoip_response.country.iso_code

    return client_lat, client_lon, client_city, client_country, client_country_code


def list_to_jsonl_gz(file_path: str, list_of_dicts: List[dict]):
    """ Takes a list of dictionaries and writes this to a gzipped jsonl file.

    :param file_path: Path to the .jsonl.gz file
    :param list_of_dicts: A list containing dictionaries that can be written out with jsonlines
    :return: None.
    """
    logging.info(f'Writing results to file: {file_path}')
    with io.BytesIO() as bytes_io:
        with gzip.GzipFile(fileobj=bytes_io, mode='w') as gzip_file:
            with jsonlines.Writer(gzip_file) as writer:
                writer.write_all(list_of_dicts)

        with open(file_path, 'wb') as jsonl_gzip_file:
            jsonl_gzip_file.write(bytes_io.getvalue())


def upload_file_to_storage_bucket(file_path: str, bucket_name: str, blob_name: str) -> bool:
    """ Upload a file to a google cloud storage bucket

    :param file_path: The local file path of the file that will be uploaded
    :param bucket_name: The storage bucket name
    :param blob_name: The blob name inside the storage bucket
    :return: Whether blob exists.
    """
    storage_client = storage.Client()
    bucket = storage_client.bucket(bucket_name)
    blob = bucket.blob(blob_name)

    logging.info(f'Uploading file "{file_path}". Blob: {blob_name}, bucket: {bucket_name}')
    blob.upload_from_filename(file_path)

    return True if blob.exists() else False
