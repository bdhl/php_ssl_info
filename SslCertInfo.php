<?php

class SslCertInfo {

	private $host;
	private $port;

	private $cert = array();
	private $cert_chain = array();

	public function __construct($host_url = '', $timeOut = 30) {
		$this->setHost($host_url, $timeOut);
	}

	public function setHost($host, $timeOut = 30) {
		if ($host) {
			@list($this->host, $this->port) = explode(':', $host);
			if (!$this->host) {
				throw new Exception("Host is empty");
			}
			$this->port = (int)$this->port > 0 ? (int)$this->port : 443;
			$this->fetchCert($timeOut);
		}
	}

	protected function fetchCert($timeOut = 30) {
		$this->cert = $this->cert_chain = array();

		if ($stream_context = stream_context_create(array(
			'ssl' => array(
				'verify_peer' => false,
				'capture_peer_cert' => true,
				'capture_peer_cert_chain' => true
			)
		))) {
			if ($socket_client = stream_socket_client(
				"ssl://{$this->host}:{$this->port}",
				$err_no,
				$err_str,
				$timeOut,
				STREAM_CLIENT_CONNECT,
				$stream_context)) {
				if ($context_param = stream_context_get_params($socket_client)) {
					if (isset($context_param['options']['ssl']['peer_certificate'])) {
						$this->cert = openssl_x509_parse($context_param['options']['ssl']['peer_certificate']);
					}

					if (isset($context_param['options']['ssl']['peer_certificate_chain']) &&
						sizeof($context_param['options']['ssl']['peer_certificate_chain']) >0 ) {
						foreach ($context_param['options']['ssl']['peer_certificate_chain'] as $chain) {
							$this->cert_chain[] = openssl_x509_parse($chain);
						}
					}
				} else {
					throw new Exception("Fetched empty context param");
				}
			} else {
				throw new Exception("Can't connect to host. Error: {$err_no} {$err_str}");
			}
		} else {
			throw new Exception("Can't create stream context");
		}
	}

	public function getCert() {
		return $this->cert;
	}

	public function getCertChain() {
		return $this->cert_chain;
	}
}
