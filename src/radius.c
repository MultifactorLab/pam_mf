
#include "radius.h"
/**************************************************************************
 * MISC FUNCTIONS
 **************************************************************************/

/** A strerror_r() wrapper function to deal with its nuisances.
 *
 * @param[in] errnum		syslog priority id
 * @param[in] buf	        Variadic arguments
 * @param[in] buflen	    Variadic arguments
 */
static void get_error_string(int errnum, char *buf, size_t buflen)
{
#if !defined(__GLIBC__) || ((_POSIX_C_SOURCE >= 200112L || _XOPEN_SOURCE >= 600) && ! _GNU_SOURCE)
	/* XSI version of strerror_r(). */
	int retval = strerror_r(errnum, buf, buflen);

	/* POSIX does not state what will happen to the buffer if the function fails.
	 * Put it into a known state rather than leave it possibly uninitialized. */
	if (retval != 0 && buflen > (size_t)0) {
		buf[0] = '\0';
	}
#else
	/* GNU version of strerror_r(). */
	char tmp_buf[BUFFER_SIZE];
	char *retval = strerror_r(errnum, tmp_buf, sizeof(tmp_buf));

	snprintf(buf, buflen, "%s", retval);
#endif
}

/** Return an IP address as a struct sockaddr
 *
 * @param[in] host		Hostname
 * @param[out] addr	    sockaddr buffer
 * @param[in] port	    used port
 * @return
 *	- returns zero on success or one of the error codes listed in gai_strerror(3)
 *    if an error occurs
 */
static int get_ipaddr(CONST char *host, struct sockaddr *addr, CONST char *port)
{
	struct addrinfo hints;
	struct addrinfo *results;
	int retval;

	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	retval = getaddrinfo(host, port && port[0] ? port : NULL, &hints, &results);
	if (retval == 0) {
		memcpy(addr, results->ai_addr, results->ai_addrlen);
		freeaddrinfo(results);
	}

	return retval;
}

/** Do XOR of two buffers.
 */
static uint8_t * xor(uint8_t *p, uint8_t *q, int length)
{
	uint8_t *retval= p;
	int i;

	for (i = 0; i < length; i++) *(p++) ^= *(q++);

	return retval;
}

/**************************************************************************
 * MID-LEVEL RADIUS CODE
 **************************************************************************/

/* get a pseudo-random vector.
 */
static void get_random_vector(uint8_t *vector)
{
#ifdef linux
	int total = 0;
	int fd;

	fd = open("/dev/urandom", O_RDONLY); /* Linux: get *real* random numbers */
	if (fd >= 0) {
		while (total < AUTH_VECTOR_LEN) {
			int bytes = read(fd, vector + total, AUTH_VECTOR_LEN - total);
			if (bytes <= 0)	break;			/* oops! Error */
			total += bytes;
		}

		close(fd);
	}

	if (total != AUTH_VECTOR_LEN)
#endif
	{				/* do this *always* on other platforms */
		MD5_CTX my_md5;
		struct timeval tv;
		struct timezone tz;
		static unsigned int session = 0; /* make the number harder to guess */

		/**
		 * Use the time of day with the best resolution the system can
		 * give us -- often close to microsecond accuracy.
		 */
		gettimeofday(&tv,&tz);

		if (session == 0) session = getppid();	/* (possibly) hard to guess information */

		tv.tv_sec ^= getpid() * session++;

		/* Hash things to get maybe cryptographically strong pseudo-random numbers */
		MD5Init(&my_md5);
		MD5Update(&my_md5, (uint8_t *) &tv, sizeof(tv));
		MD5Update(&my_md5, (uint8_t *) &tz, sizeof(tz));
		MD5Final(vector, &my_md5);				/* set the final vector */
	}
}


/**
 * Verify the response from the server
 */
static int verify_packet(CONST char *secret, AUTH_HDR *response, AUTH_HDR *request)
{
	MD5_CTX my_md5;
	uint8_t calculated[AUTH_VECTOR_LEN];
	uint8_t reply[AUTH_VECTOR_LEN];

	/*
	 * We could dispense with the memcpy, and do MD5's of the packet
	 * + vector piece by piece.	This is easier understand, and maybe faster.
	 */
	memcpy(reply, response->vector, AUTH_VECTOR_LEN); /* save the reply */
	memcpy(response->vector, request->vector, AUTH_VECTOR_LEN); /* sent vector */

	/* MD5(response packet header + vector + response packet data + secret) */
	MD5Init(&my_md5);
	MD5Update(&my_md5, (uint8_t *) response, ntohs(response->length));

	/*
	 * This next bit is necessary because of a bug in the original Livingston
	 * RADIUS server.	The authentication vector is *supposed* to be MD5'd
	 * with the old password (as the secret) for password changes.
	 * However, the old password isn't used.	The "authentication" vector
	 * for the server reply packet is simply the MD5 of the reply packet.
	 * Odd, the code is 99% there, but the old password is never copied
	 * to the secret!
	 */
	if (*secret) MD5Update(&my_md5, (CONST uint8_t *) secret, strlen(secret));

	MD5Final(calculated, &my_md5);			/* set the final vector */

	/* Did he use the same random vector + shared secret? */
	if (memcmp(calculated, reply, AUTH_VECTOR_LEN) != 0) return FALSE;

	return TRUE;
}

/**
 * Find an attribute in a RADIUS packet.	Note that the packet length
 * is *always* kept in network byte order.
 */
static attribute_t *find_attribute(AUTH_HDR *response, uint8_t type)
{
	attribute_t *attr = (attribute_t *) &response->data;
	uint16_t len;

	len = (ntohs(response->length) - AUTH_HDR_LEN);

	while (attr->attribute != type) {
		if ((len -= attr->length) <= 0) return NULL;		/* not found */

		attr = (attribute_t *) ((char *) attr + attr->length);
	}

	return attr;
}

/**
 * Add an attribute to a RADIUS packet.
 */
static void add_attribute(AUTH_HDR *request, uint8_t type, CONST uint8_t *data, int length)
{
	attribute_t *p;

	p = (attribute_t *) ((uint8_t *)request + ntohs(request->length));
	p->attribute = type;
	p->length = length + 2;		/* the total size of the attribute */

	request->length = htons(ntohs(request->length) + p->length);

	memcpy(p->data, data, length);
}

/**
 * Add an integer attribute to a RADIUS packet.
 */
static void add_int_attribute(AUTH_HDR *request, uint8_t type, int data)
{
	uint32_t value = htonl(data);

	add_attribute(request, type, (uint8_t *) &value, sizeof(value));
}

static void add_vendor_attribute(AUTH_HDR *request, int vendorId, int type, CONST uint8_t *data, int length)
{
	attribute_t *p;

	p = (attribute_t *) ((uint8_t *)request + ntohs(request->length));
	p->attribute = PW_VENDOR_SPECIFIC;
	p->length = length + 8;		/* the total size of the attribute */
	request->length = htons(ntohs(request->length) + p->length);
	uint32_t value = htonl(vendorId);

	memcpy(p->data, (uint8_t *) &value, sizeof(value));
	*(p->data+4)=(uint8_t)type;
	*(p->data+5)=(uint8_t)length+2;
	memcpy(p->data+6, data, length);
}

static void add_nas_ip_address(AUTH_HDR *request, CONST char *hostname) {
	struct addrinfo hints;
	struct addrinfo *ai_start;
	struct addrinfo *ai;
	int v4seen = 0, v6seen = 0;
	int r;

	memset(&hints, 0, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_ADDRCONFIG;

	r = getaddrinfo(hostname, NULL, &hints, &ai_start);
	if (r != 0)	return;

	ai = ai_start;
	while (ai != NULL) {
		if (!v4seen && ai->ai_family == AF_INET) {
			v4seen = 1;

			r = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;

			add_int_attribute(request, PW_NAS_IP_ADDRESS, ntohl(r));
		}

		if (!v6seen && ai->ai_family == AF_INET6) {
			v6seen = 1;

			add_attribute(request, PW_NAS_IPV6_ADDRESS,
				(uint8_t *) &((struct sockaddr_in6 *)ai->ai_addr)->sin6_addr, 16);
		}

		ai = ai->ai_next;
	}

	freeaddrinfo(ai_start);
}

/*
 * Add a RADIUS password attribute to the packet.	Some magic is done here.
 *
 * If it's an PW_OLD_PASSWORD attribute, it's encrypted using the encrypted
 * PW_PASSWORD attribute as the initialization vector.
 *
 * If the password attribute already exists, it's over-written.	This allows
 * us to simply call add_password to update the password for different
 * servers.
 */
static void add_password(AUTH_HDR *request, uint8_t type, CONST char *password, CONST char *secret)
{
	MD5_CTX md5_secret, my_md5;
	uint8_t misc[AUTH_VECTOR_LEN];
	int i;
	int length = strlen(password);
	uint8_t hashed[256 + AUTH_PASS_LEN];	/* can't be longer than this */
	uint8_t *vector;
	attribute_t *attr;

	if (length > MAXPASS) {				    /* shorten the password for now */
		length = MAXPASS;
	}

	memcpy(hashed, password, length);
	memset(hashed + length, 0, sizeof(hashed) - length);

	if (length == 0) {
		length = AUTH_PASS_LEN;			    /* 0 maps to 16 */
	} if ((length & (AUTH_PASS_LEN - 1)) != 0) {
		length += (AUTH_PASS_LEN - 1);		/* round it up */
		length &= ~(AUTH_PASS_LEN - 1);		/* chop it off */
	}						/* 16*N maps to itself */

	attr = find_attribute(request, PW_PASSWORD);

	if (type == PW_PASSWORD) {
		vector = request->vector;
	} else {
		vector = attr->data;			    /* attr CANNOT be NULL here. */
	}

	/* ************************************************************ */
	/* encrypt the password */
	/* password : e[0] = p[0] ^ MD5(secret + vector) */
	MD5Init(&md5_secret);
	MD5Update(&md5_secret, (CONST uint8_t *) secret, strlen(secret));
	my_md5 = md5_secret;				/* so we won't re-do the hash later */
	MD5Update(&my_md5, vector, AUTH_VECTOR_LEN);
	MD5Final(misc, &my_md5);			/* set the final vector */
	xor(hashed, misc, AUTH_PASS_LEN);

	/* For each step through, e[i] = p[i] ^ MD5(secret + e[i-1]) */
	for (i = 1; i < (length >> 4); i++) {
		my_md5 = md5_secret;			/* grab old value of the hash */
		MD5Update(&my_md5, &hashed[(i-1) * AUTH_PASS_LEN], AUTH_PASS_LEN);
		MD5Final(misc, &my_md5);			/* set the final vector */
		xor(&hashed[i * AUTH_PASS_LEN], misc, AUTH_PASS_LEN);
	}

	if (type == PW_OLD_PASSWORD) {
		attr = find_attribute(request, PW_OLD_PASSWORD);
	}

	if (!attr) {
		add_attribute(request, type, hashed, length);
	} else {
		memcpy(attr->data, hashed, length); /* overwrite the packet */
	}
}
int initSock(struct sockaddr *ip)
{
        struct sockaddr_storage salocal;
        memset(&salocal, 0, sizeof(salocal));
	if (ip->sa_family == AF_INET) 
		((struct sockaddr *)&salocal)->sa_family = AF_INET;
	else 
		((struct sockaddr *)&salocal)->sa_family = AF_INET6;
	int sockfd = socket(ip->sa_family, SOCK_DGRAM, 0);
        if(sockfd < 0) return -1;
#ifndef HAVE_POLL_H
	if (sockfd >= FD_SETSIZE) {
		close(sockfd);
		return -1;
	}
#endif
        if (bind(sockfd, (struct sockaddr *)&salocal, ip->sa_family == AF_INET?sizeof (struct sockaddr_in):sizeof (struct sockaddr_in6)) < 0) {
		close(sockfd);
		return -1;
	}
        return sockfd;
}
int sendPacket(AUTH_HDR *request, int sockfd,struct sockaddr *ip, char *secret,int delay, int numRetry, char *state, char *reply)
{
#ifdef HAVE_POLL_H
	struct pollfd pollfds[1];
#else
	fd_set set;
#endif
	struct timeval tv;
	time_t now, end;
        int rcode;
	socklen_t salen;
	int total_length= ntohs(request->length);
	char recv_buffer[4096];
	AUTH_HDR *response = (AUTH_HDR *) recv_buffer;
        memset(response, 0, sizeof(AUTH_HDR));
	if (ip->sa_family == AF_INET)  salen = sizeof(struct sockaddr_in);
	else salen = sizeof(struct sockaddr_in6);
        while(numRetry>0) {
        	if (sendto(sockfd, (char *) request, total_length, 0, ip, salen) < 0) 	
			return _GEN_ERROR;
		time(&now);
		tv.tv_sec = delay; 
		tv.tv_usec = 0;
		end = now + tv.tv_sec;

#ifdef HAVE_POLL_H
		pollfds[0].fd = sockfd;   /* wait only for the RADIUS UDP socket */
		pollfds[0].events = POLLIN;     /* wait for data to read */
#else
		FD_ZERO(&set);                  /* clear out the set */
		FD_SET(sockfd, &set);     /* wait only for the RADIUS UDP socket */
#endif
                for(;;) {
#ifdef HAVE_POLL_H
			rcode = poll((struct pollfd *) &pollfds, 1, tv.tv_sec * 1000);
#else
			rcode = select(sockfd + 1, &set, NULL, NULL, &tv);
#endif
			if (rcode == 0) break;
			else if (rcode < 0) {
				if (errno == EINTR) {	/* we were interrupted */
					time(&now);
					if (now > end) break;
					tv.tv_sec = end - now;
					if (tv.tv_sec == 0) tv.tv_sec = 1;
				} else return _GEN_ERROR;			/* not an interrupt, it was a real error */
			
#ifdef HAVE_POLL_H
			} else if (pollfds[0].revents & POLLIN) {
#else
			} else if (FD_ISSET(sockfd, &set)) {
#endif
                       		if ((total_length = recvfrom(sockfd, (void *) response, BUFFER_SIZE, 0, NULL, NULL)) < 0) 
					return _GEN_ERROR;
                                if ((ntohs(response->length) != total_length) || (ntohs(response->length) > BUFFER_SIZE)) 
                                	return _WRONG_PACKED;
				if (!verify_packet(secret, response, request)) 
					return _WRONG_PACKED;
                                if (response->id != request->id)
					return _WRONG_PACKED;
				attribute_t *a_state = find_attribute(response, PW_STATE);
				attribute_t *a_reply = find_attribute(response, PW_REPLY_MESSAGE);
                                if(a_state!=NULL && state!=NULL && a_state->length>2) {
					memcpy(state,a_state->data, a_state->length - 2);
					state[a_state->length - 2] = 0;
				}
                                if(a_reply!=NULL && reply!=NULL && a_reply->length>2) {
					memcpy(reply,a_reply->data, a_reply->length - 2);
					reply[a_reply->length - 2] = 0;
				}
				return response->code;	 
			}
                }
		numRetry--;
		
	}
	return _HOST_NOT_ANSWERED;
}
int chkRadius(char* host, char* port, char* secret, char* nas,int delay, int numRetry, char *reply)
{
        
	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;

        struct sockaddr_storage ip_storage;
        struct sockaddr *ip=(struct sockaddr *)&ip_storage;
        int retval,sockfd;
	retval = get_ipaddr(host, ip, port);
        if(retval!=0) return _HOST_NOT_FOUND;
        sockfd=initSock(ip);
        if(sockfd<0) return _GEN_ERROR;

	request->code = PW_STATUS_SERVER;
	get_random_vector(request->vector);
	request->id = 0;
	request->length = htons(AUTH_HDR_LEN);

        if(nas && strlen(nas)>0) 
        	add_attribute(request, PW_NAS_IDENTIFIER, nas, strlen(nas));
        retval=sendPacket(request,sockfd,ip,secret,delay,numRetry,NULL,reply);
        close(sockfd);
	return retval;
}
int sendRequest(int Id, char* host, char* port, char* secret, char* nas, char* userName, char* pass,char* stationId,int delay, int numRetry, char *state, char *reply)
{
	char hostname[256];
	hostname[0] = '\0';
	gethostname(hostname, sizeof(hostname) - 1);

	char send_buffer[4096];
	AUTH_HDR *request = (AUTH_HDR *) send_buffer;

        struct sockaddr_storage ip_storage;
        struct sockaddr *ip=(struct sockaddr *)&ip_storage;
        int retval,sockfd;
	retval = get_ipaddr(host, ip, port);
        if(retval!=0) return _HOST_NOT_FOUND;
        sockfd=initSock(ip);
        if(sockfd<0) return _GEN_ERROR;

	request->code = PW_AUTHENTICATION_REQUEST;
	get_random_vector(request->vector);
	request->id = Id;
	request->length = htons(AUTH_HDR_LEN);

	add_attribute(request, PW_USER_NAME, (CONST uint8_t *) userName, strlen(userName));
        add_vendor_attribute(request,774641,1,"MFpam",5);
        add_vendor_attribute(request,774641,2,"1.0.0",5);
	add_attribute(request, PW_CALLED_STATION_ID, (CONST uint8_t *) hostname, strlen(hostname));
        if(stationId && strlen(stationId)>0) 
		add_attribute(request, PW_CALLING_STATION_ID, (CONST uint8_t *) stationId, strlen(stationId));
	else
		add_attribute(request, PW_CALLING_STATION_ID, (CONST uint8_t *) hostname, strlen(hostname));
        if(pass && strlen(pass)>0) 
		add_password(request, PW_PASSWORD, pass, secret);
        if(nas && strlen(nas)>0) 
        	add_attribute(request, PW_NAS_IDENTIFIER, nas, strlen(nas));
        if(state && strlen(state)>0) {
        	add_attribute(request, PW_STATE, state, strlen(state));
		state[0]=0;
	}
        if(reply) reply[0]=0;
        retval=sendPacket(request,sockfd,ip,secret,delay,numRetry,state,reply);
        close(sockfd);
	return retval;

}