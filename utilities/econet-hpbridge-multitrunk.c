/*
  (c) 2025 Chris Royle
    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>.

*/

/*
 * econet-hpbridge-multitrunk.c
 *
 * Contains the despatcher routine for multitrunks.
 *
 * When a multitrunk client is initialized, it will have its
 * mt_parent pointer set to one of these despatcher objects.
 * As the TCP listener socket can be created to listen on
 * IPv4 and IPv6 at the same time, each such multitrunk
 * server object only listens on a single TCP socket.
 *
 * At startup, it will create a pipe2() pair for each
 * client trunk that is associated to it via its mt_parent
 * pointer. Those pipe2() pairs will use
 * O_NONBLOCK and O_DIRECT so that packets sent and 
 * received from the client trunks go as a single
 * unit, like they are doing on UDP at the moment.
 *
 * It'll lock the client trunk and put that pair of ints
 * into the client's mt_socket array. The client will
 * have slept on a signal, which this despatcher will
 * wake up when it finds traffic for those trunks.
 *
 * When this thread gets a new connection, it'll put it on
 * its list of "unknown trunk" connections and wait for
 * traffic. It'll sit listening for traffic on those connections
 * and looks for the '*' packet start marker. It then receives
 * the following Base64 data (upto 32k in 8bit form) up to
 * a '*' packet end marker. 
 *
 * If the multitrunk doesn't yet know the key for the traffic,
 * it works through each multitrunk client object (by
 * iterating over *trunks) and tries to find one under lock
 * which is (i) attached to this multitrunk and (ii) is marked
 * inactive. If that trunk's key successfully decrypts the 
 * traffic then the key is copied into local storage and used
 * thereafter. The socket is added to the list of sockets the
 * multitrunk object listens on, together with the appropriate
 * member of the socketpair() pair, in order to receive traffic
 * for outbound transmission.
 *
 * If no such trunk is found, the connection is simply closed.
 *
 * If the TCP connection drops, the trunk client is locked,
 * marked inactive, and a bridge reset triggered.
 * 
 */

#define _GNU_SOURCE

#include "econet-hpbridge.h"

/* 
 * Multitrunk transceiver thread
 *
 * Parameter is pointer to struct mt_client
 *
 * Spawned by server or client device threads.
 *
 * If started by client thread, then *trunk and key will be populated already.
 * If started by server thread, we'll need to wait for received traffic,
 * find a trunk within *trunks that matches and decrypts successfully and then
 * populate.
 *
 * On disconnection, just clear out the necessary data in the underlying
 * trunk to flag it as inactive, lock the multitrunk struct & splice out
 * our device, and then the thread dies - we wait for server or client to
 * start a new one. Probably need to wake the client thread somehow to
 * get it to start trying to connect unconnected multitrunks again.
 */

/* eb_trunk_decrypt
 *
 * Uses the SSL library to decrypt an encrypted packet, and leaves it in
 * newly malloc()ed dec_data (length dec_datalen), which must be 
 * free()d by the caller at some stage.
 *
 * returns length of decrypted data at dec_data if successful (bytes)
 * or -1 for failure
 */

int32_t	eb_trunk_decrypt(uint16_t port, uint8_t *cipherpacket, uint32_t length, unsigned char *sharedkey, uint8_t *dec_data)
{

	EVP_CIPHER_CTX  *ctx_dec; // Encryption control
	int		encrypted_length;
	uint8_t		temp_packet[ECONET_MAX_PACKET_SIZE+6];
	uint16_t	datalength;
	int32_t		dec_datalen = 0;

	if (!(ctx_dec = EVP_CIPHER_CTX_new()))
		eb_debug (1, 0, "(M)TRUNK", "(M)Trunk %7d Failed to establish decrypt cipher control!", port);

	 eb_debug (0, 4, "(M)TRUNK", "(M)Trunk %7d Encrypted trunk packet received - type %d, IV bytes %02x %02x %02x ...", port, cipherpacket[TRUNK_CIPHER_ALG], cipherpacket[TRUNK_CIPHER_IV], cipherpacket[TRUNK_CIPHER_IV+1], cipherpacket[TRUNK_CIPHER_IV+2]);

	switch (cipherpacket[TRUNK_CIPHER_ALG])
	{
		case 1:
			EVP_DecryptInit_ex(ctx_dec, EVP_aes_256_cbc(), NULL, sharedkey, &(cipherpacket[TRUNK_CIPHER_IV]));
			break;
		default:
			eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d Encryption type %02x in encrypted unknown - discarded", port, cipherpacket[TRUNK_CIPHER_ALG]);
			break;
	}

	if (cipherpacket[TRUNK_CIPHER_ALG] && (cipherpacket[TRUNK_CIPHER_ALG] <= 1))
	{

		int     tmp_len;

		eb_debug (0, 4, "(M)TRUNK", "(M)Trunk %7d Encryption type in encrypted is valid - %02x; encrypted data length %04x", port, cipherpacket[TRUNK_CIPHER_ALG], (length - TRUNK_CIPHER_DATA));

		if ((!EVP_DecryptUpdate(ctx_dec, temp_packet, &(encrypted_length), (unsigned char *) &(cipherpacket[TRUNK_CIPHER_DATA]), length - TRUNK_CIPHER_DATA)))
			eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d DecryptUpdate of trunk packet failed", port);
		else if (EVP_DecryptFinal_ex(ctx_dec, (unsigned char *) &(temp_packet[encrypted_length]), &tmp_len))
		{
			encrypted_length += tmp_len;

			eb_debug (0, 4, "(M)TRUNK", "(M)Trunk %7d Trunk packet length %04x", port, encrypted_length);

			datalength = (temp_packet[0] * 256) + temp_packet[1];

			if (datalength >= 12) // Valid packet size received
			{
				eb_debug (0, 4, "(M)TRUNK", "(M)Trunk %7d Encrypted trunk packet validly received - specified length %04x, decrypted length %04x, marking receipt at %d seconds", port, datalength, encrypted_length, time(NULL));

				dec_data = eb_malloc(__FILE__, __LINE__, "(M)TRUNK", "Allocate memory for decrypted packet received on trunk", datalength);

				memcpy(dec_data, &(temp_packet[2]), datalength); // data length always ignores the ECONET part of the data
				dec_datalen = datalength;
			}
			else
				eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d Decrypted trunk packet too small (data length = %04x) - discarded", port, datalength);
		}
		else
			eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d DecryptFinal of trunk packet failed - decrypted length before call was %04x", port, encrypted_length);
	}

	EVP_CIPHER_CTX_free(ctx_dec);
	
	if (dec_datalen == 0)
		return -1;
	else	return datalength;
}

/*
 * eb_trunk_encrypt
 *
 * Takes a raw packet at *packet, length
 * and encrypts using the data using the key etc within device 'd'.
 * Puts the encrypted data at *encrypted (which is malloc()ed here and must be free()d by the caller).
 * Returns length of encrypted data
 *
 * We can safely rely on knowing what 'd' is by this stage, because multitrunks don't transmit
 * anything except a welcome message until they've received some encrypted data and 
 * figured out which trunk client is talking to them.
 *
 * NB length parameter INCLUDES the 12 byte bridge trunk header length.
 *
 */

int32_t	eb_trunk_encrypt (uint8_t *packet, uint16_t length, uint16_t port, struct __eb_device *d, uint8_t **encrypted)
{

	EVP_CIPHER_CTX	*ctx_enc;
	unsigned char	iv[EVP_MAX_IV_LENGTH];
	uint8_t		cipherpacket[TRUNK_CIPHER_TOTAL];
	uint8_t		temp_packet[ECONET_MAX_PACKET_SIZE + 12 + 2];
	int		encrypted_length, tmp_len;
	
	RAND_bytes(iv, AES_BLOCK_SIZE);

	cipherpacket[TRUNK_CIPHER_ALG] = 1;

	memcpy(&(cipherpacket[TRUNK_CIPHER_IV]), &iv, EVP_MAX_IV_LENGTH);

	temp_packet[0] = (length & 0xff00) >> 8;
	temp_packet[1] = (length & 0x00ff);

	memcpy (&(temp_packet[2]), packet, length);

	if (!(ctx_enc = EVP_CIPHER_CTX_new()))
		eb_debug (1, 0, "(M)TRUNK", "(M)Trunk %7d Unable to set up encryption control", port);

	EVP_EncryptInit_ex(ctx_enc, EVP_aes_256_cbc(), NULL, d->trunk.sharedkey, iv);

	if ((!EVP_EncryptUpdate(ctx_enc, (unsigned char *) &(cipherpacket[TRUNK_CIPHER_DATA]), &encrypted_length, temp_packet, length + 2))) // +2 for the length bytes inserted above
	{
		eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d EncryptUpdate of (m)trunk packet failed", port);
		encrypted_length = 0;
	}
	else if ((!EVP_EncryptFinal(ctx_enc, (unsigned char *) &(cipherpacket[TRUNK_CIPHER_DATA + encrypted_length]), &tmp_len)))
	{
		eb_debug (0, 2, "(M)TRUNK", "(M)Trunk %7d EncryptFinal of (m)trunk packet failed", port);
		encrypted_length = 0;
	}
	else
	{
		encrypted_length += tmp_len;
		eb_debug (0, 4, "(M)TRUNK", "(M)Trunk %7d Encryption succeeded: cleartext length %04X, encrypted length %04X", length + 2, encrypted_length);
	}

	EVP_CIPHER_CTX_free(ctx_enc);

	if (encrypted_length > 0)
	{
		*encrypted = eb_malloc(__FILE__, __LINE__, "(M)TRUNK", "New encrypted packet", encrypted_length);
		memcpy (*encrypted, &cipherpacket, encrypted_length);
		return encrypted_length;
	}

	return -1; // Failure

}

/* eb_multitrunk_find_marker
 *
 * Find * or & in stream starting at start, up to maximum of length
 */

int16_t eb_multitrunk_find_marker (uint8_t *data, uint16_t start, uint16_t length)
{
	uint16_t count = 0;

	while ((start + count) < length)
	{
		if (*(data + start + count) == '*' || *(data + start + count) == '&')
			return (start + count);
		count++;
	}

	return -1;
}

/* eb_mt_copy_to_cipherpacket
 *
 * Copies new inbound data to the end of a cipherpacket structure and
 * updates the pointers
 */

uint8_t eb_mt_copy_to_cipherpacket (uint8_t **cipherpacket, uint32_t *cipherpacket_ptr, uint32_t *cipherpacket_size, uint8_t *buffer, uint16_t start, uint16_t length)
{
	uint32_t	realloc_size = *cipherpacket_size + length;
	uint32_t	copylength = length;
	uint32_t	copystart = start;
	uint8_t		ret = 1; /* Success */

	if (!*cipherpacket) /* Need space */
		*cipherpacket_ptr = 0;

	if ((*cipherpacket_ptr + length) > EB_MT_TCP_MAXSIZE)
	{
		/* Too big. Wrap around */

		*cipherpacket_ptr = 0;
		realloc_size = (*cipherpacket_ptr + length) % EB_MT_TCP_MAXSIZE;
		copylength = realloc_size;
		copystart = length - realloc_size;

		ret = 0; /* Overran */
	}
	
	if (!*cipherpacket)
	{
		*cipherpacket_ptr = 0;
		realloc_size = length > EB_MT_TCP_MAXSIZE ? EB_MT_TCP_MAXSIZE : length;
		//fprintf (stderr, "\n\n*** Cipherpacket null - allocating %d bytes***\n\n", realloc_size);
		*cipherpacket = eb_malloc(__FILE__, __LINE__, "MTRUNK", "New cipherpacket", realloc_size);
	}
	else
	{
		//fprintf (stderr, "\n\n*** Cipherpacket not null - re-allocating to %d***\n\n", realloc_size);
		*cipherpacket = realloc(cipherpacket, realloc_size);
	}

	memcpy ((*cipherpacket + *cipherpacket_ptr), (buffer + copystart), copylength);

	*cipherpacket_ptr += copylength;
	*cipherpacket_size = realloc_size;

	return ret;
}

/* 
 * eb_mt_send_proto_version
 *
 * Send our local protocol version to the other side.
 *
 */

void eb_mt_send_proto_version (struct mt_client *me)
{
	uint8_t		data[3] = { EB_MT_CMD_VERS, 0, EB_MT_PROTOCOL_VERSION };

	eb_mt_base64_encrypt_tx (data, 3, me->trunk, '&');

	me->mt_local_version = EB_MT_PROTOCOL_VERSION;

	eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Sent multitrunk protocol version %d to %s:%d", 
			me->multitrunk_parent->multitrunk.port,
			EB_MT_PROTOCOL_VERSION,
			me->trunk->trunk.hostname,
			me->trunk->trunk.remote_port);
}

/* eb_mt_process_admin_packet
 *
 * Handles processing of administrative packets received on multitrunks
 */

void eb_mt_process_admin_packet (struct mt_client *me, uint8_t *cipherpacket, char *remotehost, uint16_t remoteport)
{
	switch (*cipherpacket)
	{
		case EB_MT_CMD_VERS:
			me->mt_remote_version = *(cipherpacket + 2);
			eb_debug (0, 1, "MTRUNK", "M-Trunk %7d Multitrunk protocol version %02d from %s:%d", me->multitrunk_parent->multitrunk.port, me->mt_remote_version, remotehost, remoteport);
			break;
		default:
			eb_debug (0, 1, "MTRUNK", "M-Trunk %7d Unknown multitrunk admin command %02X from %s:%d", me->multitrunk_parent->multitrunk.port, *(cipherpacket), remotehost, remoteport);
			break;
	}
}

/* 
 * b_mt_debase64_decrypt_process
 *
 * Undo base64 encoding in place using glib-2.0 (and barf if fails)
 * Then decrypt - finding trunk if we don't know which one it is
 * Then process - admin or other packet
 *
 * returns 1 for success, 0 for failure
 */

uint8_t eb_mt_debase64_decrypt_process(struct mt_client *me, uint8_t *cipherpacket, uint16_t length, char *remotehost, uint16_t remoteport)
{

	int32_t		decrypted_length;
	uint32_t	size = length;

	struct __eb_device	*search_trunk;

	eb_debug (0, 3, "MTRUNK", "M-Trunk  %7d Processing incoming base64 data of length %d from %s:%d %c %c %c %c", me->multitrunk_parent->multitrunk.port, length, remotehost, remoteport, *(cipherpacket), *(cipherpacket+1), *(cipherpacket+2), *(cipherpacket+3));

	/* Undo Base64 in place */

	g_base64_decode_inplace ((gchar *) cipherpacket, (gsize *) &size);

	/* Now decrypt */

	search_trunk = trunks;

	if (me->trunk)
		search_trunk = me->trunk; // If we alread know which one, the while loop will find it immediately

	/* Look for a trunk with matching data - needs to be attached to our multitrunk, and if it's connected and mt_cilent is set and isn't me then dump the older connection */

	while (search_trunk)
	{
		if (search_trunk->trunk.mt_parent && search_trunk->trunk.mt_type == MT_SERVER) /* I.e. the trunk is a multitrunk child and is a server instance, so we can accept connections and this might therefore be one whose key we can check decryption on */
		{
			uint8_t	buffer[ECONET_MAX_PACKET_SIZE+12];

			/* Attempt a decrypt with its key */

			/* Probably want to curtail encrypted data which is too long... TODO! */

			if ((decrypted_length = eb_trunk_decrypt(me->multitrunk_parent->multitrunk.port, cipherpacket, size, search_trunk->trunk.sharedkey, buffer)) >= 0)
			{
				fprintf (stderr, "\n\n*** Decryptable packet received, length %d\n\n", decrypted_length);

				pthread_mutex_lock(&(search_trunk->trunk.mt_mutex));

				/* If trunk already connected to another handler, set its death flag */
				
				if ((search_trunk->trunk.mt_data) && (search_trunk->trunk.mt_data != me))
				{
					search_trunk->trunk.mt_data->death = 1; /* Kill it */
					search_trunk->trunk.mt_data = me;
				}

				me->trunk = search_trunk;

				/* If marker = &, call eb_mt_process_admin_packet, or otherwise write to the trunk child */

				if (me->marker == '&')
					eb_mt_process_admin_packet(me, buffer, remotehost, remoteport);
				else /* Write to underlying trunk */
					write (me->trunk_socket, buffer, decrypted_length);

				me->marker = 0;

				pthread_mutex_unlock(&(search_trunk->trunk.mt_mutex));

				if (me->mt_local_version == 0)
					eb_mt_send_proto_version(me);

				return 1;
			}
			else /* Move to next trunk */
				search_trunk = search_trunk->next;

		}
		else
			search_trunk = search_trunk->next;
	}

	/* If we get here, we couldn't decrypt - fail */

	eb_debug (0, 2, "MTRUNK", "M-Trunk  %7d Undecryptable packet received from %s:%d length %d", me->multitrunk_parent->multitrunk.port, remotehost, remoteport, length);
	me->marker = 0;
	return 0;

}

/*
 * eb_mt_base64_encrypt_tx
 *
 * Take cleartext packet data, encrypt it, base64 it, and
 * transmit it with multitrunk delimeters on the socket associated
 * with the multitrunk of which it's a child.
 *
 */

int eb_mt_base64_encrypt_tx(uint8_t *data, uint16_t datalength, struct __eb_device *mt, char delimiter)
{

	gchar 		* base64;
	uint8_t		* base64_terminated;
	uint8_t		* encrypted;
	uint16_t	encrypted_length;

	if ((encrypted_length = eb_trunk_encrypt(data, datalength, mt->trunk.local_port, mt, &encrypted)) >= 0)
	{
		base64 = g_base64_encode((const guchar *) encrypted, encrypted_length);

		if (base64)
		{
			int send_result;
			uint16_t	terminated_length;

			terminated_length = strlen(base64)+3;

			base64_terminated = eb_malloc(__FILE__, __LINE__, "M-Trunk", "New base64 terminated packet", terminated_length);
			*base64_terminated = delimiter;
			memcpy ((base64_terminated+1), base64, strlen(base64));
			*(base64_terminated + terminated_length - 1) = delimiter;
			*(base64_terminated + terminated_length) = '\0';
		
			g_free(base64); // No need for this any more	

			/* The mt_mutex is already locked before this function gets called, and we 
			 * have already checked mt_data is valid
			 */

			send_result = send(mt->trunk.mt_data->socket, base64_terminated, terminated_length, MSG_DONTWAIT);
			if (send_result != terminated_length)
			{
				if (send_result == -1) /* Error */
					eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Unable to transmit multitrunk data - %s", mt->trunk.local_port, strerror(errno));
				else
					eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Unable to transmit multitrunk data - tx was %d bytes not %d", mt->trunk.local_port, send_result, terminated_length);
			}
			return send_result;

		}
		else /* Failure? */
		{
			eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Unable to transmit multitrunk data - Base64 encode failed", mt->trunk.local_port);
			return -1;
		}

		eb_free(__FILE__, __LINE__, "M-Trunk", "Free cipher data on MT transmission", encrypted);

	}
	else /* Encryption failure */
	{
		eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Unable to transmit multitrunk data - Encryption failed", mt->trunk.local_port);
		return -1;
	}

	/* Should never get here */

	return -1;
}

/* 
 * eb_mt_set_endpoint_name
 *
 * Set the endpoint name and port on a multitrunk child trunk device.
 *
 */

void eb_mt_set_endpoint (struct __eb_device *mtc, char *remotehost, uint16_t remoteport)
{

	mtc->trunk.hostname = eb_malloc(__FILE__, __LINE__, "M-TRUNK", "Allocate new remote hostname string", strlen(remotehost)+1);
	strcpy(mtc->trunk.hostname, remotehost);
	mtc->trunk.remote_port = remoteport;
}

/*
 * eb_mt_unset_endpoint_name
 *
 * Unset the endpoint name and port on a multitrunk child trunk device. Really only for server type devices where
 * we may not have a connection to the other end we can initiate.
 */

void eb_mt_unset_endpoint (struct __eb_device *mtc)
{
	if (mtc->trunk.hostname)
		eb_free(__FILE__, __LINE__, "M-TRUNK", "Free trunk hostname string", mtc->trunk.hostname);
	mtc->trunk.hostname = NULL;
	mtc->trunk.remote_port = 0;
}

/* Bidirectional traffic from an underlying trunk device to the multitrunk socket (whether acccept()ed inbound, or connect()ed outbound */

void * eb_multitrunk_handler_thread (void * input)
{
	struct mt_client	* me;
	//struct pollfd		p[2];
	struct pollfd		p;
	uint8_t			*cipherpacket = NULL;
	uint32_t		cipherpacket_ptr = 0, cipherpacket_size = 0; // _ptr is pointer into cipherpacket, _size is current allocated size of cipherpacket, which will grow in EB_MT_TCP_CHUNKSIZE chunks up to EB_MT_TCPMAXSIZE
	union	{
			struct sockaddr_in	mt_sockaddr_in;
			struct sockaddr_in6	mt_sockaddr_in6;
	} mt_sa;
	socklen_t		mt_sa_len = sizeof(mt_sa);
	char 			remoteip[32];
	uint16_t		remoteport;
	char			remotehost[HOST_NAME_MAX];

	me = (struct mt_client *) input; // Once we've found the underlying trunk, we copy this pointer into its mt_client struct in the device so that it can be found by later connections

	/* When called, the trunk which might be being connected to is unknown.
	 * What we have to do is receive some traffic, deBase64 it, and
	 * then attempt to decrypt by reference to all the keys we have for
	 * distant systems which support TCP. If we don't find one, we'll close
	 * the connection and die.
	 *
	 * If we do, we'll populate me->trunk and that tells us where to find the
	 * key subsequently. We also update the pipe pair
	 * multitrunk master field in the underlying trunk so that it knows
	 * it is operational.
	 *
	 * For now, we'll set up the state machine.
	 */

	/* No need to lock until the mt_client struct is populated into an underlying trunk because nothing else can find it until then. */

	me->mt_state = MT_IDLE;
	me->mt_local_version = 0; // Means not yet announced to other end
	me->mt_remote_version = 1; // Unknown yet, assume 1 unless we hear otherwise.

	eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d New thread spawned for connection", me->multitrunk_parent->multitrunk.port);

	if (getpeername(me->socket, (struct sockaddr *)&mt_sa, &mt_sa_len) == -1) 
	{
		eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Unable to look up peer name for connection", me->multitrunk_parent->multitrunk.port);
		close(me->socket);
		return NULL;
	}

	switch (mt_sa.mt_sockaddr_in.sin_family)
	{
		case AF_INET:
			inet_ntop(AF_INET, &(((struct sockaddr_in *) &(mt_sa.mt_sockaddr_in))->sin_addr),
					remoteip,
					127);
			remoteport = ntohs(mt_sa.mt_sockaddr_in.sin_port);
			break;
		case AF_INET6:
			inet_ntop(AF_INET6, &(((struct sockaddr_in6 *) &(mt_sa.mt_sockaddr_in6))->sin6_addr),
					remoteip,
					127);
			remoteport = ntohs(mt_sa.mt_sockaddr_in6.sin6_port);
			break;
		default:
			eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Wrong socket type for connection", me->multitrunk_parent->multitrunk.port);
			close(me->socket);
			return NULL;
			break;
	}

	if (getnameinfo((struct sockaddr *) &(mt_sa), mt_sa_len, remotehost, HOST_NAME_MAX-1, NULL, 0, NI_NAMEREQD))
	{
		eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Unable to resolve hostname for %s:%d", me->multitrunk_parent->multitrunk.port, remoteip, remoteport);
		strcpy(remotehost, remoteip);
	}

	eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d New connection with remote at %s(%s):%d", me->multitrunk_parent->multitrunk.port, remotehost, remoteip, remoteport);

	if (me->trunk->trunk.mt_type == MT_SERVER) /* Update endpoint address in trunk */
		eb_mt_set_endpoint (me->trunk, remotehost, remoteport);

	if ((me->trunk_socket = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK, 0)) == -1)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Unable to create socket to underlying trunk", me->multitrunk_parent->multitrunk.port);

	/* Lock the underlying trunk and update its mt_data */

	pthread_mutex_lock(&(me->trunk->trunk.mt_mutex));
	me->trunk->trunk.mt_data = me;
	pthread_mutex_unlock(&(me->trunk->trunk.mt_mutex));

	/* 
	 * Protocol v1:
	 * Administrative packets are '&' (base64(encrypted)) '&' 
	 * Data packets are '*' (base64(encrypted)) '*'
	 */

	/* Administrative packets have the following format:
	 * byte 0	Command
	 * 		1 - Announce protocol version (EB_MT_CMD_VERS)
	 * byte 1	Sub-command
	 * 		(Nothing at present)
	 * bytes 2+	Data
	 * 		For version, this is a 1 byte value
	 */

	if (me->trunk->trunk.mt_type == MT_CLIENT) /* We need to send our version number up front */
		eb_mt_send_proto_version(me);

	/* The server can't transmit until it's received something from the client, but the client can because it knows the shared key */

	/* Except a welcome message which does nothing */

	write (me->socket, "$$$" EB_MT_WELCOME_MSG "$$$\r\n", strlen(EB_MT_WELCOME_MSG) + 8);

	/* Wake up the device listener */

	pthread_cond_broadcast(&(me->trunk->trunk.mt_cond)); // Wakes up BOTH eb_device_listener and eb_device_despatcher

	/* Wait for data */

	/* Change to comms arrangements - we only listen on our TCP socket; underlying trunk writes directly out */

	p.fd = me->socket;
	p.events = POLLIN;
	p.revents = 0;

	/*
	p[0].fd = me->socket;
	p[0].events = POLLIN;
	p[0].revents = 0;

	p[1].fd = me->mt_pipe[0]; // Read side from underlying trunk
	p[1].events = POLLIN;
	p[1].revents = 0;
	*/


	while (1) /* We break if we want to die */
	{

		while ((poll(&p, 1, 1000) == 0) && me->death == 0)
		{ }

		if (p.revents & POLLHUP) /* This may not be working... */
			break; // Graceful death
			
		pthread_mutex_lock(&(me->mt_lock));

		if (me->death) // Graceful death
		{
			pthread_mutex_unlock(&(me->mt_lock));
			break;
		}

		pthread_mutex_unlock(&(me->mt_lock));

		if (p.revents & POLLIN)
		{
			/* Data on our TCP socket */
			uint8_t		buffer[EB_MT_TCP_CHUNKSIZE];
			int16_t		ptr = 0, my_ptr = 0;
			int		len;
			int16_t		realdata_start = -1, realdata_len = 0;

			len = read (me->socket, buffer, EB_MT_TCP_CHUNKSIZE);

			if (len == 0) /* Socket closure? */
			{
				// Not clear why we needed to be locked at this stage
				// pthread_mutex_unlock(&(me->mt_lock));
				break;
			}

			eb_debug (0, 3, "MTRUNK", "M-Trunk  %7d Data received from %s:%d length %d", me->multitrunk_parent->multitrunk.port, remotehost, remoteport, len);

			if (len == -1) // Error - quit
			{
				// Not clear why we needed to be locked at this stage
				// pthread_mutex_unlock(&(me->mt_lock));
				break;
			}

			if ((cipherpacket_size - cipherpacket_ptr) < len)
			{
				/* Expand buffer, up to maximum */

				cipherpacket_size = (cipherpacket_size + len) < EB_MT_TCP_MAXSIZE ? (cipherpacket_size + len) : EB_MT_TCP_MAXSIZE;
				cipherpacket = realloc(cipherpacket, cipherpacket_size);
			}

			/* What state are we in? */

			my_ptr = 0; // Look through the received data & process

			while (my_ptr < len)
			{
				
				switch (me->mt_state)
				{
					case MT_IDLE: /* Waiting for start character, so look for it */
					{
						if (cipherpacket) /* Free memory if currently in use */
						{
							eb_free(__FILE__, __LINE__, "MTRUNK", "Free current inbound packet memory ready for new reception", cipherpacket);
							cipherpacket = NULL;
							cipherpacket_size = cipherpacket_ptr = 0;
						}

						if ((ptr = eb_multitrunk_find_marker(buffer, my_ptr, len)) >= 0) /* Marker found */ 
						{ 
							me->mt_state = MT_START; // move state
							me->marker = buffer[ptr]; // Copy start marker
	
							if ((ptr+2) < len) /* +2 because if e.g. len = 7, and data[6] '*' then there's no real data here - we're just at start of data packet  */
							{
								realdata_start = ++ptr;
	
								if ((ptr = eb_multitrunk_find_marker(buffer, ptr, len)) >= 0) /* Close marker found */
								{
									realdata_len = ptr - realdata_start;								 
	
									fprintf (stderr, "\n\n*** Found end marker - realdata_len = %d, cipherpacket = %p ***\n\n", realdata_len, cipherpacket);

									eb_mt_copy_to_cipherpacket (&cipherpacket, &cipherpacket_ptr, &cipherpacket_size, buffer, realdata_start, realdata_len);

									fprintf (stderr, "\n\n*** Cipherpacket = %p ***\n\n", cipherpacket);

									eb_mt_debase64_decrypt_process(me, cipherpacket, cipherpacket_ptr, remotehost, remoteport);

									cipherpacket = NULL;

									/* Update my_ptr for while loop */
	
									my_ptr = ptr+1;

									me->mt_state = MT_IDLE; // Look for another start
	
								}
								else /* Start found, but not end marker */
								{
									int16_t		copylen;
	
									my_ptr = len; /* Causes exit from while() loop */

									/* Copy balance of packet from and including realdata_start into ciphertext */
	
									copylen = len - realdata_start; 

									eb_mt_copy_to_cipherpacket (&cipherpacket, &cipherpacket_ptr, &cipherpacket_size, buffer, realdata_start, copylen);
								}
							}
						}
						else	my_ptr = len; /* Quite the while loop and do nothing */
					} break;

					case MT_START: /* Received start character, cipherpacket & cipherpacket_ptr will point to next empty slot in cipherpacket. We are now looking for data and a terminator */
					{
						/* We've had a start marker, there may or may not be data in cipherpacket, so look for end marker */
	
						if ((ptr = eb_multitrunk_find_marker(buffer, my_ptr, len)) >= 0) /* Marker found */
						{
							if (ptr > 0) /* Only copy if need be */
								eb_mt_copy_to_cipherpacket (&cipherpacket, &cipherpacket_ptr, &cipherpacket_size, buffer, 0, ptr); // ptr is pointer to the marker, so data ends at ptr-1, so ptr is equivalent to length
	
							eb_mt_debase64_decrypt_process(me, cipherpacket, cipherpacket_ptr, remotehost, remoteport);
							cipherpacket = NULL;

							my_ptr = ptr+1; /* Loop round */
	
							me->mt_state = MT_IDLE; /* Back to idle for next Econet chunk */
						}
						else
						{
							eb_mt_copy_to_cipherpacket (&cipherpacket, &cipherpacket_ptr, &cipherpacket_size, buffer, 0, len); // Copy into cipherpacket
							my_ptr = len; /* Quit loop */
						}
					} break;
				}
			}
		}

		/* Trunk will write directly to our socket  
		if (p[1].revents & POLLIN)
		{
		}
		*/

		// Not clear why we needed this lock
		// pthread_mutex_unlock(&(me->mt_lock));

		
		p.fd = me->socket;
		p.events = POLLIN;
		p.revents = 0;

		/*
		p[0].fd = me->socket;
		p[0].events = POLLIN;
		p[0].revents = 0;
	
		p[1].fd = me->mt_pipe[0]; // Read side from underlying trunk
		p[1].events = POLLIN;
		p[1].revents = 0;
		*/

	}

	eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Disconnect or read error from %s(%s):%d", me->multitrunk_parent->multitrunk.port, remotehost, remoteip, remoteport);

	/* Graceful close down and unpick links in/to underlying trunk */

	if (me->trunk)
	{
		pthread_mutex_lock(&(me->trunk->trunk.mt_mutex));
		me->trunk->trunk.mt_data = NULL; // Disconnect us

		if (me->trunk->trunk.mt_type == MT_SERVER)
			eb_mt_unset_endpoint(me->trunk);

		// Do we need to clear ->hostname, ->remote_host as well? Probably for dynamic trunks.
		pthread_mutex_unlock(&(me->trunk->trunk.mt_mutex));
	}
	close(me->trunk_socket);
	close(me->socket);

	eb_free (__FILE__, __LINE__, "M-TRUNK", "Free multitrunk handler struct mt_client", me);

	return NULL;
}

/* 
 * multitrunk client device.
 *
 * One thread of this type is started for each trunk which is
 * both a multitrunk child AND which is a client-type device
 *
 * Attempts to connect (and, when disconnected, reconnect) trunks which have
 * a defined remote endpoint and which are clients rather than servers.
 *
 * Uses locking within the (ordinary) trunk device to update all the 
 * relevant fields so that the multitrunk server doesn't accept a 
 * connection from an already connected trunk and vice versa.
 */

void * eb_multitrunk_client_device (void * device)
{
	struct __eb_device	*me; /* A trunk device */
	struct addrinfo		hints;
	struct addrinfo		*mt_addresses, *mt_iterate;
	char			portstring[10];
	int			ga_return;

	/* So a multitrunk child client device will have 
	 * hostname & remoteport set which defines where to
	 * connect. So lets resolve that and try connecting.
	 */

	me = (struct __eb_device *) device;

	eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Client to %s:%d connection thread starting", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);

	if (!me->trunk.hostname)
		eb_debug (1, 0, "M-TRUNK", "Attempt to start a multitrunk client with no hostname defined!");

	if (!me->trunk.remote_port)
		eb_debug (1, 0, "M-TRUNK", "Attempt to start a multitrunk client with no remote port defined!");

	sprintf (portstring, "%5d", me->trunk.remote_port);

	memset (&hints, 0, sizeof(hints));
	hints.ai_family = me->multitrunk.ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 6;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	eb_thread_ready();

	ga_return = EAI_AGAIN;

	while (ga_return == EAI_AGAIN)
	{
		ga_return = getaddrinfo(me->trunk.hostname, portstring, &hints, &mt_addresses);
		if (ga_return == EAI_AGAIN)
		{
			eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Client to %s:%d Temporary failure in name resolution, trying again in 10s", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
			sleep(10);
		}
	}

	if (ga_return != 0)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client to %s:%d unable to resolve address: %s", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port, gai_strerror(ga_return));

	if (mt_addresses)
		eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Client to %s:%d successfully resolved hostname", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
	else
	{
		eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Client to %s:%d getaddrinfo() returned no addresses - giving up", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
		return NULL;
	}

	while (1) /* Connect and keep trying */
	{
		int mt_socket;
		unsigned int timeout = me->trunk.mt_parent->multitrunk.timeout;
		uint8_t connected;

		mt_socket = -1;
		connected = 0;

		for (mt_iterate = mt_addresses; mt_iterate != NULL; mt_iterate = mt_iterate->ai_next)
		{

			char	hostname[256];

			switch (mt_iterate->ai_family)
			{
				case AF_INET:
					inet_ntop(AF_INET, &(((struct sockaddr_in *)mt_iterate->ai_addr)->sin_addr), hostname, mt_iterate->ai_addrlen);
					break;
				case AF_INET6:
					inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)mt_iterate->ai_addr)->sin6_addr), hostname, mt_iterate->ai_addrlen);
					break;
				default:
					strcpy (hostname, "Cannot convert hostname string");
					break;
			}

			mt_socket = socket (mt_iterate->ai_family,
						mt_iterate->ai_socktype,
						mt_iterate->ai_protocol);
	
			if (mt_socket == -1)
				eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client unable to create a required socket for connection to %s:%d", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
	
			/* - Not needed on clients?
			if (setsockopt(mt_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
				eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d unable to set SO_REUSEADDR", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
				*/
	
			if (timeout > 0 && (setsockopt(mt_socket, SOL_SOCKET, TCP_USER_TIMEOUT, (char *) &(timeout), sizeof(timeout)) < 0))
				eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d unable to set TCP_USER_TIMEOUT to %d", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port, me->trunk.mt_parent->multitrunk.timeout);

			if (connect(mt_socket, mt_iterate->ai_addr, mt_iterate->ai_addrlen) != -1)
			{
				/* Set non-blocking here rather than in the socket() call, because otherwise connect() will give us EINPROGRESS... */

				int flags;

				flags = fcntl(mt_socket, F_GETFL);

				if (flags == -1)
					eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d unable to get TCP flags in order to set O_NONBLOCK", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);

				if (fcntl(mt_socket, F_SETFL, (flags | O_NONBLOCK)) == -1)
					eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d unable to set O_NONBLOCK", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);

				connected = 1;
				break; /* Connected. If not, try the next address */
			}
			else eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Client socket to %s(%s):%d failed to connect (%s)", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, hostname, me->trunk.remote_port, strerror(errno));
		}

		if (connected)
		{
			/* Start handler */
			struct mt_client	*mtc_new;
			pthread_t		mtc_thread;
			int			mtc_err;
			void *			mtc_ret;

			/* Spawn a thread */

			mtc_new = eb_malloc(__FILE__, __LINE__, "M-TRUNK", "Allocate new client structure", sizeof(struct mt_client));

			memset(mtc_new, 0, sizeof(struct mt_client));

			mtc_new->socket = mt_socket;
			mtc_new->multitrunk_parent = me->trunk.mt_parent;
			mtc_new->trunk = me;
			mtc_new->mt_type = MT_TYPE_TCP; /* They're all TCP for now. There may be a time when
     							   we adapt this to cope with UDP too. */

			/* Initialize lock on the data */

			if (pthread_mutex_init(&(mtc_new->mt_lock), NULL) == -1)
				eb_debug(1, 0, "M-TRUNK", "M-Trunk  %7d Unable to initialize MT lock for new outbound connection to %s:%d", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);

			if ((mtc_err = pthread_create(&mtc_thread, NULL, eb_multitrunk_handler_thread, mtc_new)))
				eb_debug(1, 0, "M-TRUNK", "M-Trunk  %7d Unable to spawn new thread for outbound multitrunk connection to %s:%d", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);

			/* Wait for the handler to finish */

			pthread_join(mtc_thread, &mtc_ret);

			eb_free(__FILE__, __LINE__, "M-TRUNK", "Free used client structure", mtc_new);

			eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d closed. Re-opening.", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
		}
		else
		{
			eb_debug (0, 1, "M-TRUNK", "M-Trunk  %7d Client socket to %s:%d unable to connect to any resolved address. Re-trying.", me->trunk.mt_parent->multitrunk.port, me->trunk.hostname, me->trunk.remote_port);
			sleep (10); /* Wait ten seconds and try again from the start */
		}
	}

	return NULL;
}

/* multitrunk server device
 * listens and spins off a tcp transceiver thread for
 * each device opened
 */

void * eb_multitrunk_server_device (void * device)
{
	struct __eb_device	*me;
	struct pollfd		*fds, *fds_initial;
	uint16_t		numfds = 0; // How many things in *fds, *fds_initial
	int			ga_return, poll_return;
	struct addrinfo		hints;
	struct addrinfo		*mt_addresses, *mt_iterate;
	char			portstring[10];

	/* Note: port number & host (or NULL) to listen on are in device->multitrunk->port, device->multitrunk->host */

	me = (struct __eb_device *) device;

	sprintf (portstring, "%5d", me->multitrunk.port);

	memset (&hints, 0, sizeof(hints));
	hints.ai_family = me->multitrunk.ai_family;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = (me->multitrunk.host) ? 0 : AI_PASSIVE; // Give us the "all addresses" struct if name is null
	hints.ai_protocol = 6;
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	eb_thread_ready();

	ga_return = EAI_AGAIN;

	while (ga_return == EAI_AGAIN)
	{
		ga_return = getaddrinfo(me->multitrunk.host, portstring, &hints, &mt_addresses);
		if (ga_return == EAI_AGAIN)
		{
			eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Server on %s:%d Temporary failure in name resolution, trying again in 10s", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);
			sleep(10);
		}
	}

	if (ga_return != 0)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to resolve listen address: %s", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, gai_strerror(ga_return));

	eb_debug (0, 3, "M-TRUNK", "M-Trunk  %7d Server on %s:%d successfully resolved hostname", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);
	
	if (!mt_addresses)
		eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d getaddrinfo() returned no addresses", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

	/* Now lets create some sockets */

	for (mt_iterate = mt_addresses; mt_iterate != NULL; mt_iterate = mt_iterate->ai_next)
	{
		int mt_socket;
		int on = 1;
		unsigned int timeout = me->multitrunk.timeout;

		mt_socket = socket (mt_iterate->ai_family,
					mt_iterate->ai_socktype | SOCK_NONBLOCK,
					mt_iterate->ai_protocol);

		if (mt_socket == -1)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to create a required socket", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		if (setsockopt(mt_socket, SOL_SOCKET, SO_REUSEADDR, (char *) &on, sizeof(on)) < 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to set SO_REUSEADDR", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		if (timeout > 0 && (setsockopt(mt_socket, SOL_SOCKET, TCP_USER_TIMEOUT, (char *) &(timeout), sizeof(timeout)) < 0))
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to set TCP_USER_TIMEOUT to %d", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, me->multitrunk.timeout);

		if (bind(mt_socket, mt_iterate->ai_addr, mt_iterate->ai_addrlen) != 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to bind to %s (addr family %d)", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, mt_iterate->ai_canonname, mt_iterate->ai_protocol);

		if (listen(mt_socket, me->multitrunk.listenqueue ? me->multitrunk.listenqueue : 10) < 0)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Server on %s:%d unable to set listen queue length", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		/* Set non-blocking - inherited by children we think */

		if (numfds == 0) // fds_initial won't point to anything yet
			fds_initial = eb_malloc(__FILE__, __LINE__, "M-TRUNK", "Allocate first pollfd structure for fs_initial", sizeof(struct pollfd));
		else // Reallocate
			fds_initial = realloc(fds_initial, (numfds + 1) * sizeof(struct pollfd));

		if (!fds_initial)
			eb_debug (1, 0, "M-TRUNK", "M-Trunk  %7d Error reallocating fds structure on server %s:%d", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port);

		memset(&(fds_initial[numfds]), 0, sizeof(struct pollfd));

		fds_initial[numfds].fd = mt_socket;
		fds_initial[numfds].events = POLLIN;
		numfds++;
	}

	eb_debug (0, 2, "M-TRUNK", "M-Trunk  %7d Server on %s:%d successfully opened %d listener(s)", me->multitrunk.port, me->multitrunk.host, me->multitrunk.port, numfds);

	freeaddrinfo(mt_addresses);

	fds = eb_malloc (__FILE__, __LINE__, "M-TRUNK", "Allocate memory for list of fds to accept on", sizeof(struct pollfd) * numfds);

	memcpy (fds, fds_initial, sizeof(struct pollfd) * numfds);

	while (1) 
	{

		poll_return = poll(fds, numfds, 10000); // 10s per loop

		if (poll_return > 0)
		{
			uint16_t	count;
			int		newconn;

			/* Loop through the fds struct, accept what needs accepting, and spin off some server threads */

			for (count = 0; count < numfds; count++)
			{
				if (fds[count].revents & POLLIN)
				{
					newconn = accept(fds[count].fd, NULL, NULL);

					if (newconn >= 0)	
					{
						struct mt_client	*mtc_new;
						pthread_t		mtc_thread;
						int			mtc_err;

						/* Spawn a thread */
	
						mtc_new = eb_malloc(__FILE__, __LINE__, "M-TRUNK", "Allocate new client structure", sizeof(struct mt_client));

						memset(mtc_new, 0, sizeof(struct mt_client));

						mtc_new->socket = newconn;
						mtc_new->multitrunk_parent = me;
						mtc_new->trunk = me;
						mtc_new->mt_type = MT_TYPE_TCP; /* They're all TCP for now. There may be a time when
			     							   we adapt this to cope with UDP too. */

						/* Initialize lock on the data */

						if (pthread_mutex_init(&(mtc_new->mt_lock), NULL) == -1)
							eb_debug(1, 0, "M-TRUNK", "M-Trunk  %7d Unable to initialize MT lock for new connection", me->multitrunk.port);

						if ((mtc_err = pthread_create(&mtc_thread, NULL, eb_multitrunk_handler_thread, mtc_new)))
							eb_debug(1, 0, "M-TRUNK", "M-Trunk  %7d Unable to spawn new thread for inbound multitrunk connection", me->multitrunk.port);

						pthread_detach(mtc_thread);
					}
				}
			}
		}

		/* Go again */

		memcpy (fds, fds_initial, sizeof(struct pollfd) * numfds);

	}

	return NULL;
}

/*
 * eb_mt_find
 *
 * Find a multitrunk by name
 */

struct __eb_device * eb_mt_find (char * name)
{

	struct __eb_device *res;

	res = multitrunks;

	while (res)
	{
		if (!strcasecmp(res->multitrunk.mt_name, name))
			return res;

		else res = res->next;
	}

	return NULL; /* Not found */

}

