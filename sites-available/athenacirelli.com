##
# You should look at the following URL's in order to grasp a solid understanding
# of Nginx configuration files in order to fully unleash the power of Nginx.
# http://wiki.nginx.org/Pitfalls
# http://wiki.nginx.org/QuickStart
# http://wiki.nginx.org/Configuration
#
# Generally, you will want to move this file somewhere, and start with a clean
# file but keep this around for reference. Or just disable in sites-enabled.
#
# Please see /usr/share/doc/nginx-doc/examples/ for more detailed examples.
##

server {
	listen 80;
	listen [::]:80;

	# Make site accessible from http://localhost/
	server_name athenacirelli.com;

	root /var/www/html/athenacirelli.com/html;
	index index.html index.htm;

    access_log /var/log/nginx/athenacirelli.com/access.log;
    error_log /var/log/nginx/athenacirelli.com/error.log;

    gzip on;

	location / {
		# First attempt to serve request as file, then
		# as directory, then fall back to displaying a 404.
		try_files $uri $uri/ =404;
		# Uncomment to enable naxsi on this location
		# include /etc/nginx/naxsi.rules
	}

	error_page 404 /404.html;

	# redirect server error pages to the static page /50x.html
	#
	error_page 500 502 503 504 /50x.html;
	location = /50x.html {
		root /var/www/html/cirelli.org/html;
	}
}


# HTTPS server
#
server {
	listen 443 ssl;

	# Make site accessible from https://localhost/
	server_name athenacirelli.com;

	root /var/www/html/athenacirelli.com/html;
	index index.html index.htm;

	ssl on;

	#ssl_certificate /etc/nginx/ssl/cirelli.org/self-ssl.crt; #cert.pem;
	#ssl_certificate_key /etc/nginx/ssl/cirelli.org/self-ssl.key; #cert.key;
	#ssl_certificate /etc/letsencrypt/live/cirelli.org/cert.pem;
	ssl_certificate /etc/letsencrypt/live/cirelli.org/fullchain.pem;
	ssl_certificate_key /etc/letsencrypt/live/cirelli.org/privkey.pem;

	ssl_session_cache   shared:SSL:10m;
	ssl_session_timeout 5m;
	keepalive_timeout   60;

	ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
	#ssl_ciphers "HIGH:!aNULL:!MD5 or HIGH:!aNULL:!MD5:!3DES";
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:DHE-DSS-AES128-GCM-SHA256:kEDH+AESGCM:ECDHE-RSA-AES128-SHA256:ECDHE-ECDSA-AES128-SHA256:ECDHE-RSA-AES128-SHA:ECDHE-ECDSA-AES128-SHA:ECDHE-RSA-AES256-SHA384:ECDHE-ECDSA-AES256-SHA384:ECDHE-RSA-AES256-SHA:ECDHE-ECDSA-AES256-SHA:DHE-RSA-AES128-SHA256:DHE-RSA-AES128-SHA:DHE-DSS-AES128-SHA256:DHE-RSA-AES256-SHA256:DHE-DSS-AES256-SHA:DHE-RSA-AES256-SHA:AES128-GCM-SHA256:AES256-GCM-SHA384:AES128-SHA:AES256-SHA:AES:CAMELLIA:DES-CBC3-SHA:!aNULL:!eNULL:!EXPORT:!DES:!RC4:!MD5:!PSK:!aECDH:!EDH-DSS-DES-CBC3-SHA:!EDH-RSA-DES-CBC3-SHA:!KRB5-DES-CBC3-SHA';
	ssl_prefer_server_ciphers on;

    access_log /var/log/nginx/athenacirelli.com/ssl_athenacirelli.com_access.log;
    error_log /var/log/nginx/athenacirelli.com/ssl_athenacirelli.com_error.log;
    #log_format compression '$remote_addr - $remote_user [$time_local] ' '"$request" $status $bytes_sent ' '"$http_referer" "$http_user_agent" "$gzip_ratio"' '"$request_body_file"';

	location / {
		try_files $uri $uri/ =404;
	}

	error_page 404 /404.html;

	# redirect server error pages to the static page /50x.html
	#
	error_page 500 502 503 504 /50x.html;
	location = /50x.html {
		root /var/www/html/cirelli.org/html;
	}
}
