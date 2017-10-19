import argparse
import os
import logging
import hvac
import requests
import datetime


def vault_is_up(address, cafile):
    logging.info("checking Health of vault: " + address)
    vault_url = address + "/v1/sys/health"
    try:
        status = requests.get(vault_url, verify=cafile)
    except Exception as e:
        logging.error(e)
    if status.status_code == 200 or status.status_code == 429:
        return True
    else:
        return False


def get_certificate(address, token, cafile, ttl, cname, capath):
    logging.info("initializing vault connection client.")

    try:
        client = hvac.Client(url=address,
                             token=token,
                             verify=cafile)
        logging.info("requesting Certificate and private key from vault CA.")
        response = client.write(capath, ttl=ttl, common_name=cname)
        logging.info("Success!")
        return response
    except Exception as e:
        logging.error(e)


def write_to_disk(certificate, key, path):

    logging.info("writing certificate data to :" + path)
    cert_path = path + "cert.pem"
    key_path = path + "key.pem"

    cert_file = open(cert_path, 'w')
    cert_file.write(certificate)
    cert_file.close()

    key_file = open(key_path, 'w')
    key_file.write(key)
    key_file.close()
    logging.info("wrote certificate file to " + cert_path)
    logging.info("wrote certificate key file to " + key_path)


def main():
    logging.basicConfig(level=logging.INFO, datefmt='%Y-%m-%d %H:%M:%S',
                        format='[%(asctime)s] %(levelname)s  %(message)s')
    parser = argparse.ArgumentParser(
        description='connect to vault using parameters provided and'
                    ' issue certificate from the CA provided in the parameters')

    parser.add_argument('--cname',
                        default=os.environ.get('CNAME', None),
                        action='store', dest='CertificateCname',
                        help="<Required> set cname of the certificate",
                        type=str)

    # Usage: -s test2.service.consul test3.service.consul
    parser.add_argument('-s', '--sans', nargs='+',
                        default=os.environ.get('SANS', None),
                        action='store', dest='CertificateSANS',
                        help='<Optional> Set certificate SAN', type=list)

    parser.add_argument('-t', '--ttl',
                        default=os.environ.get('TTL', None),
                        action='store', dest='CertificateTtl',
                        help="<Required> set ttl of the certificate",
                        type=str)

    parser.add_argument('-d', '--dir',
                        default=os.environ.get('DIR', None),
                        action='store', dest='CertificateDir',
                        help="<Required> <Required> set target dir  of the certificate",
                        type=str)

    parser.add_argument('-v', '--vault-addr',
                        default=os.environ.get('VAULT_ADDR', None),
                        action='store', dest='VaultAddress',
                        help="<Required> set address of vault machine",
                        type=str)

    parser.add_argument('-p', '--ca-path',
                        default=os.environ.get('VAULT_CA_PATH', None),
                        action='store', dest='VaultCAPath',
                        help="<Required> set path of ca inside vault",
                        type=str)

    parser.add_argument('-k', '--vault-token',
                        default=os.environ.get('VAULT_TOKEN', None),
                        action='store', dest='VaultToken',
                        help="<Required> set token to access vault",
                        type=str)

    parser.add_argument('-f', '--ca-file',
                        default=os.environ.get('CA_FILE', None),
                        action='store', dest='CAFile',
                        help="<Required> CA certificate file",
                        type=str)

    args = parser.parse_args()

    if not args.VaultToken and args.TrustedCA and args.VaultAddress and args.CertificateDir and args.CertificateTtl and args.CertificateTtl and args.CertificateCname:
        os.exit(2)
    else:
        if not vault_is_up(args.VaultAddress, args.CAFile):
            logging.error("Vault is not returning 200")

        else:
            logging.info("vault seems to be healthy.")

        certificate_data = get_certificate(args.VaultAddress,
                                           args.VaultToken,
                                           args.CAFile,
                                           args.CertificateTtl,
                                           args.CertificateCname,
                                           args.VaultCAPath)

        d = datetime.timedelta(seconds=certificate_data['lease_duration'])
        new_timestamp = datetime.datetime.now() + d

        logging.info('vault request_id is: ' + certificate_data['request_id'])
        logging.info('vault lease_duration is: ' + str(certificate_data['lease_duration']) + "s")
        logging.info("certificate will expire on " + str(new_timestamp))
        logging.info('vault certificate serial number: ' + str(certificate_data['data']['serial_number']))
        logging.info('vault certificate private_key_type: ' + certificate_data['data']['private_key_type'])
        logging.info("writing to disk")

        # checks if ca_chain exists
        # if 'ca_chain' in certificate_data['data']:
        #     for chainca in certificate_data['data']['ca_chain']:
        #         print(chainca)

        try:
            write_to_disk(certificate_data['data']['certificate'], certificate_data['data']['private_key'],
                          args.CertificateDir)
            logging.info("Success!")
        except Exception as e:
            logging.error(e)


if __name__ == '__main__':
    main()
