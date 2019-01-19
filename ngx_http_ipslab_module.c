/*�ڲ�������ipslab_��ͷ
 * ģ����غ�����ngx_��ͷ
 * */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
//#include <openssl/err.h>
//#include <malloc.h>

# include <openssl/md5.h>


#define ID_POS_MIN 6
#define ID_LEN_IN_TEXT sizeof(ngx_int_t)
#define ENCRPT_ID_SIZE 33
//#define CURVE_I 8
typedef struct {
	ngx_chain_t *out_ctx;
} ngx_http_ipslab_ctx_t;

typedef struct {
	u_char rbtree_node_data;
	ngx_queue_t queue;
	u_char old_ID[ENCRPT_ID_SIZE];

} ngx_http_ipslab_node_t;

//ngx_http_ipslab_shm_t �����ڹ����ڴ���
typedef struct {
	//��������ڿ��ټ���
	ngx_rbtree_t rbtree;
	//ʹ�ú�������붨����ڱ��ڵ�
	ngx_rbtree_node_t sentinel;
	//��̭����
	ngx_queue_t queue;
} ngx_http_ipslab_shm_t;

typedef struct {
	//ssize_t shmsize;�����ڴ��С���������ʺ�ngx_int_t,�ڴ��ʺ�ʹ��ssize_t
	ngx_int_t shmsize_int;
	ngx_slab_pool_t *shpool;//���������ڴ�һ����Ҫ�Ľṹ�壬����ṹ��Ҳ�ڹ����ڴ���
	ngx_http_ipslab_shm_t *sh;
// ngx_int_t uri_ID;
} ngx_http_ipslab_conf_t;
static ngx_int_t ngx_http_ipslab_handler(ngx_http_request_t *r);
static char * ngx_http_ipslab_createmem(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf);
static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf);
static void *ngx_http_ipslab_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ipslab_subrequest_post_handler(ngx_http_request_t *r,
		void *data, ngx_int_t rc);
static void
ipslab_post_handler(ngx_http_request_t * r);
//8888static ngx_int_t ngx_http_ipslab_input_filter(void *data, ssize_t bytes);

static ngx_command_t ngx_http_ipslab_commands[] = { {
ngx_string("ip_slab"),
NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1, ngx_http_ipslab_createmem, //ngx_conf_set_num_slot,
		NGX_HTTP_MAIN_CONF_OFFSET, offsetof(ngx_http_ipslab_conf_t,
				shmsize_int),
		NULL },

ngx_null_command };

static ngx_http_module_t ngx_http_ipslab_module_ctx = {
NULL, /* preconfiguration */
ngx_http_ipslab_init, /* postconfiguration */

ngx_http_ipslab_create_main_conf, /* create main configuration */
NULL, /* init main configuration */

NULL, /* create server configuration */
NULL, /* merge server configuration */

NULL, // create location configuration */
		NULL /* merge location configuration */
};

ngx_module_t ngx_http_ipslab_module = {
NGX_MODULE_V1, &ngx_http_ipslab_module_ctx, /* module context */
ngx_http_ipslab_commands, /* module directives */
NGX_HTTP_MODULE, /* module type */
NULL, /* init master */
NULL, /* init module */
NULL, /* init process */
NULL, /* init thread */
NULL, /* exit thread */
NULL, /* exit process */
NULL, /* exit master */
NGX_MODULE_V1_PADDING };

static void *ngx_http_ipslab_create_main_conf(ngx_conf_t *cf) {

	ngx_http_ipslab_conf_t *conf;
	ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
			"sxx-ngx_http_ipslab_create_main_conf");
	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipslab_conf_t));

	if (NULL == conf) {
		return NULL;
	}

	conf->shmsize_int = NGX_CONF_UNSET;
	return conf;
}

static ngx_int_t ngx_http_ipslab_shm_init(ngx_shm_zone_t *shm_zone, void *data) {
	ngx_http_ipslab_conf_t *conf;

	ngx_http_ipslab_conf_t *oconf = data;
	size_t len;
	fprintf(stderr, "%s", "ngx_http_ipslab_shm_init");
	conf = (ngx_http_ipslab_conf_t *) shm_zone->data;

	if (oconf) {
		conf->sh = oconf->sh;
		conf->shpool = oconf->shpool;

		return NGX_OK;
	}

	conf->shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;
	fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n", (char *) conf->shpool);
	if (NULL != conf->shpool) {

	}
	// fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n",conf->shpool,sizeof(ngx_slab_pool_t));
	len = sizeof(ngx_http_ipslab_shm_t);
	fprintf(stderr, "alloc:%uz", (unsigned int) len);
	conf->sh = ngx_slab_alloc(conf->shpool, 1);
	// conf->sh = ngx_slab_alloc(conf->shpool, sizeof(ngx_http_ipslab_shm_t));
	fprintf(stderr, "alloc:%uz", (unsigned int) len);
	if (conf->sh == NULL) {
		fprintf(stderr, "%s", "conf->sh == NULL");
		return NGX_ERROR;
	}
	fprintf(stderr, "%s", "before conf->shpool->data");
	conf->shpool->data = conf->sh;
	fprintf(stderr, "%s", "before ngx_rbtree_init");
	ngx_rbtree_init(&conf->sh->rbtree, &conf->sh->sentinel,
			ngx_rbtree_insert_value);

	fprintf(stderr, "%s", "before ngx_queue_init");
	ngx_queue_init(&conf->sh->queue);

	len = sizeof(" in ipslab \"\"") + shm_zone->shm.name.len;

	conf->shpool->log_ctx = ngx_slab_alloc(conf->shpool, len);
	if (conf->shpool->log_ctx == NULL) {
		return NGX_ERROR;
	}

	ngx_sprintf(conf->shpool->log_ctx, " in ipslab \"%V\"%z",
			&shm_zone->shm.name);
	fprintf(stderr, "alloc:%uz", (unsigned int) len);

	return NGX_OK;
}

static char * ngx_http_ipslab_createmem(ngx_conf_t *cf, ngx_command_t *cmd,
		void *conf) {
	ngx_str_t *value;
	ngx_http_ipslab_conf_t *mconf;

	ngx_shm_zone_t *shm_zone;
	ngx_str_t slabname = ngx_string("ip_slab_shm");

	value = cf->args->elts;
	mconf = (ngx_http_ipslab_conf_t *) conf;
	if (cf->args->nelts > 1) {
		//���ַ���תΪ����
		mconf->shmsize_int = ngx_atoi(value[1].data, value[1].len);
		if (mconf->shmsize_int == NGX_ERROR) {
			return "transform from str to int fail";
		}
	}

	shm_zone = ngx_shared_memory_add(cf, &slabname,
			mconf->shmsize_int * ngx_pagesize, &ngx_http_ipslab_module);
	fprintf(stderr, "ngx_pagesize:%d\r\n", (int) ngx_pagesize);
	fprintf(stderr, "ngx_http_ipslab_shm_init:%s\r\n", (char *) shm_zone);
	fprintf(stderr, "203\r\n");

	if (NULL == shm_zone) {
		fprintf(stderr, "%s", "(NULL == shm_zone)");
		return NGX_CONF_ERROR ;
	}
	//fprintf(stderr, "ngx_http_ipslab_createmem:%d\r\n",(uint)&shm_zone);
	shm_zone->init = ngx_http_ipslab_shm_init;
	shm_zone->data = mconf;
	ngx_log_error(NGX_LOG_DEBUG, cf->log, 0,
				"sxx-log-ngx_http_ipslab_createmem:]");
		fprintf(stderr, "sxx-fpf-ngx_http_ipslab_createmem:]");
	fprintf(stderr, "221\r\n");

	return NGX_CONF_OK;

}

/**/
static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf)
//static ngx_int_t ngx_http_ipslab_init(ngx_conf_t *cf, EC_KEY* key, u_char* retID)
{
	ngx_http_handler_pt *h;
	ngx_http_core_main_conf_t *cmcf; //ֻ��main�����

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (NULL == h) {
		return NGX_ERROR;
	}
	*h = ngx_http_ipslab_handler;
	return NGX_OK;
}
/*ngx_int_t ipslab_print_EC_KEY(EC_KEY* key)
{
	//if(key->meth == NULL) fprintf(stderr,"key->meth == NULL");
	return 1;

}*/
ngx_int_t ipslab_encrypt_mssg(u_char* mssg,u_char* encrptMssg){
	//������Ҫ���ܵ�ԭ��Ϣmessg��������ż��ܺ���Ϣ��encrptMssg
	//
	//ʹ����Բ���ܽ��м���
	/*EC_KEY *key1;
	int crv_len;
	 unsigned int nid,ret,sig_len,size;
	EC_builtin_curve *curves;
	EC_GROUP *group1;


	// ���� EC_KEY ���ݽṹ
	key1=EC_KEY_new();
	    if(key1==NULL)
	    {
	        printf("EC_KEY_new err!\n");
	        return -1;
	    }
	//��ȡʵ�ֵ���Բ���߸���
    crv_len = EC_get_builtin_curves(NULL, 0);
    curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
    // ��ȡ��Բ�����б�
    EC_get_builtin_curves(curves, crv_len);
    // ѡȡһ����Բ����
      nid=curves[CURVE_I].nid;
      fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg nid:%d",nid);
      fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg comment:%s",curves[25].comment);
	 group1=EC_GROUP_new_by_curve_name(nid);
	 if(group1==NULL)
	 {
		 printf("EC_GROUP_new_by_curve_name err!\n");
		 return -1;
	 }
	 // ������Կ����
	ret=EC_KEY_set_group(key1,group1);
	if(ret!=1)
	{
		printf("EC_KEY_set_group err.\n");
		return -1;
	}
	// ������Կ
	ret=EC_KEY_generate_key(key1);
	if(ret!=1)
	{
		printf("EC_KEY_generate_key err.\n");
		return -1;
	}

	//��ȡ��Կ��С
	size=ECDSA_size(key1);
	fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg:size:%i]\r\n",size);
	//fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg:EC_KEY key1:%s]\r\n",key1->meth);
	//fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg:EC_KEY key1:%s]\r\n",key1->engine);
	fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg:EC_KEY key1:%d]\r\n",EC_KEY_get0_public_key(key1));





	//ǩ�����ݿɽ� digest �е����ݿ����� sha1 ժҪ���
	    ret=ECDSA_sign(0,mssg,20,encrptMssg,&sig_len,key1);
	    fprintf(stderr,"sxx-fpf-ipslab_encrypt_mssg:encrptMssg:%s]\r\n",encrptMssg);
	    fprintf(stderr,"ipslab_encrypt_mssg:mssg:%s]\r\n",mssg);
	    if(ret!=1)
	    {

	    	fprintf(stderr,"sign err!\n");
	        return -1;
	    }

	       EC_KEY_free(key1);


	      free(curves);*/
	/*char* tmp_mssg = mssg;
	char* tmp_encrptMssg =
	 MD5(mssg,strlen((char*)mssg),encrptMssg);*/
	/*MD5_CTX md5;
	ngx_int_t size;
	size = strlen((char *)mssg);
	if (!MD5_Init(&md5)){
			printf("MD5_Init error\n");
			return -1;
		}

		if (!MD5_Update(&md5, mssg,size)){
			printf("MD5_Update error\n");
			return -1;
		}
		if (!MD5_Final(encrptMssg, &md5))
		{
			printf("MD5_Final error\n");
			return -1;
		}
		for (int i = 0;i<32;i++){
			printf("%02X", encrptMssg[i]);
		}
*/
	//ngx_memcpy(encrptMssg,tmp_encrptMssg,);
	 unsigned char md[16];
	 int i;

	 char tmp[3];
	 ngx_memset(tmp,'\0',3);
	 MD5(mssg,strlen((char*)mssg),md);
	 for (i = 0; i < 16; i++){
	         sprintf(tmp,"%2.2x",md[i]);

	         strcat((char*)encrptMssg,tmp);
	     }
	 fprintf(stderr,"ipslab_encrypt_mssg:encrptMssg:%s]\r\n",encrptMssg);
	 fprintf(stderr,"ipslab_encrypt_mssg:mssg:%s]\r\n",mssg);

	      return 1;
}
ngx_int_t ipslab_func_ID_getnext(u_char* old_ID,u_char* next_ID) {
	//���𽫺�����д����oldID��������õ�
	//������

	//u_char *tmp_ID = malloc(ENCRPT_ID_SIZE);
	//memcpy(tmp_ID, old_ID, ENCRPT_ID_SIZE);

	// �����Կ
	//ret = EC_KEY_check_key(key);
	//if (ret != 1) {		fprintf(stderr, "%s", "sxx-testecc-check key err.\n");
	//	return -1;	}
	//����old_ID����next_ID
	ipslab_encrypt_mssg(old_ID,next_ID);
	//����old_ID����next_ID ����n����old_ID
	ngx_memcpy(old_ID,next_ID,ENCRPT_ID_SIZE-1);
	return 1;
}

ngx_int_t ipslab_func_IDnew(u_char* encryptedID) {
	//������ �������ܵ�encryptedID��
	//1.��ʱ����Ϊԭʼ��Ϣmssg��2.���ܵõ�encryptedID

	u_char tmpID[ENCRPT_ID_SIZE];
	//1.��ʱ����Ϊԭʼ��Ϣmssg
	ngx_time_t *tp;
	ngx_msec_t now;	  //������ngx_uint_t;
	tp = ngx_timeofday();
	now = (ngx_msec_t) (tp->sec * 1000 + tp->msec);
	fprintf(stderr, "mesc-now:%d", (int) now);
	//itoa������һ����׼��C����������Windows���еģ����Ҫд��ƽ̨�ĳ�������sprintf
	sprintf((char *)tmpID,"%d",(int)now);
fprintf(stderr,"sxx-fpf-ipslab_func_IDnew: tmpID: %s]",tmpID);
	//2.���ܵõ�encryptedID


	ipslab_func_ID_getnext(tmpID, encryptedID);
	fprintf(stderr,"sxx-fpf-ipslab_func_IDnew: encryptedID: %s]",encryptedID);

	return 1;
}

static ngx_int_t ngx_abstract_hxID(ngx_http_request_t *r, ngx_int_t* begin_pos,ngx_int_t* end_pos)
//find_pos��hxID=xxxx��xxxx��ʼ��λ��
{
	ngx_int_t isAuth = -1;
	ngx_str_t match = ngx_string("hxID=");
	ngx_str_t hxID_str;

	//ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-ngx_abstract_hxID r->args:%V\r\n",r->args);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-ngx_abstract_hxID &r->args:%V\r\n", &(r->args));

	//��args��ÿ���ֶν��бȽ�
	ngx_uint_t i = 0;
	if (r->args.len >= match.len) {
		for (; i <= r->args.len - match.len; i++) {
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-i:%ui\r\n",
					i);
			if (0 == ngx_strncasecmp(r->args.data + i, match.data, match.len)) {
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
						"0 == ngx_strncasecmp\r\n,i:%ui\r\n", i);
				if (i != 0 && *(r->args.data + i - 1) != '&') {
					continue;
				}
				isAuth = i + match.len;
				break;
			}
		}
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-Auth:%ui\r\n",
				isAuth);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-r->args.len:%ui\r\n", r->args.len);

		if (-1 != isAuth) {
			for (i = isAuth; i < r->args.len; i++) {

				if (*(r->args.data + i) == '&') {
					break;
				}
			}
			hxID_str.len = i - isAuth;
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-hxID_str.len:%ui\r\n", hxID_str.len);
			/*ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-*(r->args.data+r->args.len):%s]\r\n",
					*(r->args.data));*/
			hxID_str.data = ngx_palloc(r->pool, hxID_str.len);
			ngx_memcpy(hxID_str.data, r->args.data + isAuth, i - isAuth);
			*begin_pos = isAuth;
			*end_pos = i;

			fprintf(stderr, "ngx_abstract_hxID data:try");
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
								"sxx-ngx_abstract_hxID data str:%V\r\n", &hxID_str);
			/*
			//fprintf(stderr, "ngx_abstract_hxID.len:%d\r\n",len);
			hxID_tmp = ngx_atoi(hxID_str.data, hxID_str.len);
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-ngx_abstract_hxID data int:%i\r\n", hxID_tmp);*/
			return 1;//hxID_tmp;
		}
	}

	return -1;
}
/* ɾ�����һ���ڵ�*/
static void ngx_http_ipslab_delete_one(ngx_http_request_t *r,
		ngx_http_ipslab_conf_t *conf) {

	ngx_queue_t *q;
	ngx_rbtree_node_t *node;
	ngx_http_ipslab_node_t *lr;

	if (ngx_queue_empty(&conf->sh->queue)) {
		return;
	}

	q = ngx_queue_last(&conf->sh->queue);

	lr = ngx_queue_data(q, ngx_http_ipslab_node_t, queue);

	node = (ngx_rbtree_node_t *) ((u_char *) lr
			- offsetof(ngx_rbtree_node_t, data));

	ngx_queue_remove(q);

	ngx_rbtree_delete(&conf->sh->rbtree, node);

	ngx_slab_free_locked(conf->shpool, node);

}
static ngx_int_t ngx_http_ipslab_lookup(ngx_http_request_t *r,
		ngx_http_ipslab_conf_t *conf, ngx_uint_t ip_int,
		u_char* server_ID)
//--hash��ip��hash
{

	size_t size;
	ngx_rbtree_node_t *node, *sentinel;
	ngx_http_ipslab_node_t *lr;


	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup:now I am here L414\r\n");
	//ngx_atoi(r->args->data,sizeof(ngx_int_t));
	node = conf->sh->rbtree.root;
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup:now I am here L417\r\n");
	sentinel = conf->sh->rbtree.sentinel;
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
						"sxx-log-ngx_http_ipslab_lookup:now I am here");

	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_lookup:now I am here L422\r\n");
	while (node != sentinel) {
		if (ip_int < node->key) {
			node = node->left;
			continue;
		}

		if (ip_int > node->key) {
			node = node->right;
			continue;
		}
		if (ip_int == node->key)	  //ID��ƥ����Ȼ�����������������طŹ���
			{
			lr = (ngx_http_ipslab_node_t *) &node->data;
			ngx_queue_remove(&lr->queue);
			ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
			//��ʱ���²����ظ��º�ID

			ngx_log_error(8, r->connection->log, 0,	"sxxx-ip_int == node->key,lr->old_ID before IDnext():%s", lr->old_ID);
			//lr->old_ID=ngx_func_IDnext(id_tmp);
			ipslab_func_ID_getnext(lr->old_ID,server_ID);
			ngx_log_error(8, r->connection->log, 0,	"sxxx-ip_int == node->key,lr->old_ID after IDnext():%s", lr->old_ID);
			//ngx_log_error(8, r->connection->log, 0,"sxxx-find,server_ID after IDnext():%i", (int )lr->old_ID);
			//ngx_log_error(8, r->connection->log, 0, "sxxx-IDnext:%i",(int )lr->old_ID);

			return 1;
		}

		//����
		// if(lr==NULL) printf("printf:%s","OK");

	}

	size = offsetof(ngx_rbtree_node_t,
			data) + sizeof(ngx_http_ipslab_node_t)+ENCRPT_ID_SIZE;

	node = ngx_slab_alloc_locked(conf->shpool, size);

	while (node == NULL) {
		//ɾ�����һ��,����һ�����ռ�
		ngx_http_ipslab_delete_one(r, conf);
		node = ngx_slab_alloc_locked(conf->shpool, size);
	}

	node->key = ip_int;

	lr = (ngx_http_ipslab_node_t *) &node->data;

	// retNewID = (u_char *)malloc(ENCRPT_ID_SIZE);free(retNewID);
	fprintf(stderr,"in func lookup,before IDnew, server_ID:%s]",server_ID);
	ipslab_func_IDnew(server_ID);
	fprintf(stderr,"sxx-fpf-ngx_http_ipslab_lookup:after IDnew, server_ID:%s]",server_ID);

	ngx_memcpy(lr->old_ID,server_ID,ENCRPT_ID_SIZE-1);
//ngx_memcpy(lr->old_ID,retNewID,ENCRPT_ID_SIZE);

	//ngx_log_error(8, r->connection->log, 0, "sxxx-IDnew-in lookup:%i",(int )lr->old_ID);

	// lr->ip_int=ngx_http_variable_binary_remote_addr();
	// r->connection->addr_text;
	//ngx_memcpy(lr->data, ip, len);

	ngx_rbtree_insert(&conf->sh->rbtree, node);

	ngx_queue_insert_head(&conf->sh->queue, &lr->queue);
	//memcpy(server_ID, lr->old_ID, ENCRPT_ID_SIZE);
	return 1;
}
static void ipslab_post_handler(ngx_http_request_t * r) {

	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	//���û�з���200��ֱ�ӰѴ����뷢���û�
	if (r->headers_out.status != NGX_HTTP_OK) {
		ngx_http_finalize_request(r, r->headers_out.status);
		return;
	}
	//��ǰ�����Ǹ�����ֱ��ȡ��������
	ngx_http_ipslab_ctx_t* myctx = ngx_http_get_module_ctx(r,
			ngx_http_ipslab_module);

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-log-mytest_post_handlerctx %s", myctx->out_ctx->buf->pos);
	fprintf(stderr, "%s", "sxx-fpf-mytest_post_handler");
	// system("C:\\Users\\shao\\Desktop\\JsPTest\\run.bat");
	// system("C:/Users/shao/Desktop/JsPTest/run.bat");
	// system("C://Users//shao//Desktop//JsPTest//run.bat");
	//����Content-Type��ע�⺺�ֱ������˷�����ʹ����GBK
	/* 	static ngx_str_t type = ngx_string("text/plain; charset=GBK");
	 r->headers_out.content_type = type;
	 r->headers_out.status = NGX_HTTP_OK;
	 sssssss
	 r->connection->buffered |= NGX_HTTP_WRITE_BUFFERED;*/
	ngx_int_t ret = ngx_http_send_header(r);
	// = ngx_http_output_filter(r, &out);
	ret = ngx_http_output_filter(r, myctx->out_ctx);

	//ע�⣬���﷢������Ӧ������ֶ�����ngx_http_finalize_request
	//����������Ϊ��ʱhttp��ܲ����ٰ�æ������
	ngx_http_finalize_request(r, ret);
	return;

}

static ngx_int_t ipslab_subrequest_post_handler(ngx_http_request_t *r,
		void *data, ngx_int_t rc) {

	//��ǰ����r������������parent��Ա��ָ������
	ngx_http_request_t *pr = r->parent;
	//ע�⣬�������Ǳ����ڸ������еģ��μ�5.6.5�ڣ�������Ҫ��pr��ȡ�����ġ�
//��ʵ�и��򵥵ķ�����������data���������ģ���ʼ��subrequestʱ
//���ǾͶ�����������˵ģ������Ϊ��˵����λ�ȡ���������������
	//ngx_http_mytest_ctx_t* myctx = ngx_http_get_module_ctx(pr, ngx_http_mytest_module);

	pr->headers_out.status = r->headers_out.status;
	pr->headers_out.content_type = r->headers_out.content_type;
	//�������NGX_HTTP_OK��Ҳ����200����ζ�ŷ������˷������ɹ������Ž�
//��ʼ����http����
	if (r->headers_out.status == NGX_HTTP_OK) {

		//�ڲ�ת����Ӧʱ��buffer�лᱣ�������η���������Ӧ���ر�����ʹ��
//�������ģ��������η�����ʱ�������ʹ��upstream����ʱû���ض���
//input_filter������upstream����Ĭ�ϵ�input_filter��������ͼ
//�����е�������Ӧȫ�����浽buffer��������
		ngx_buf_t* pRecvBuf = &r->upstream->buffer;

		ngx_buf_t *b;
		size_t len;
		ngx_http_ipslab_ctx_t* out = (ngx_http_ipslab_ctx_t *) data;
		//8888r->upstream->resolved->
		//88888for(;pRecvBuf->last_buf != 1;pRecvBuf = pRecvBuf->);
		len = pRecvBuf->last - pRecvBuf->pos;
		b = ngx_create_temp_buf(pr->pool, len);
		//b= out->out_ctx->buf;

		fprintf(stderr, "%s",
				"sxx-fpf-mytest_subrequest_post_handler before memcpy");

		// ngx_memcpy(pr->out->buf->pos,pRecvBuf->pos,(u_char *)pRecvBuf->last-(u_char *)pRecvBuf->pos);//((u_char *)pRecvBuf->last-(u_char *)pRecvBuf->pos)
		ngx_memcpy(b->pos, pRecvBuf->pos, len); //((u_char *)pRecvBuf->last-(u_char *)pRecvBuf->pos)
		/* ngx_str_t str_keshan = ngx_string("kehsan");
		 len =str_keshan.len;//pRecvBuf->last-pRecvBuf->pos;

		 ngx_memcpy(b->pos,str_keshan.data,len);*/
		fprintf(stderr, "len%d", (int) len);

		b->last = b->pos + len;
		b->last_buf = 1;
		fprintf(stderr, "%s", "I am here");
		out->out_ctx->buf = b;
		out->out_ctx->next = NULL;
		//for(;pRecvBuf->pos != pRecvBuf->last;)


		fprintf(stderr, "%s", "I am here");
		fprintf(stderr, "%s",
				"sxx-fpf-mytest_subrequest_post_handler after memcpy");

	} else {
		fprintf(stderr, "%s",
				"sxx-fpf-mytest_subrequest_post_handler  r->headers_out.status != NGX_HTTP_OK");

	}

	//��һ������Ҫ�����ý�����������Ļص�����
	pr->write_event_handler = ipslab_post_handler;

	return NGX_OK;
}

/*static ngx_int_t
 ngx_func_build_warningPage(ngx_buf_t* b, ngx_int_t hxID,ngx_http_request_t* r)
 {
 ngx_int_t maxlen;
 ngx_str_t str0 = ngx_string("<html><body><h1>a.html,λ����E:\\ProgramNoInstall\\nginx\\html</h1><a id = 'OneHref' href= '");

 ngx_str_t str1 = ngx_string("' onclick = 'doSomething()'>����b/b.nmj </a><script type='text/javascript'> var hxID = ");
 ngx_str_t str2 = ngx_string(";\r\n function doSomething()\r\n{\r\nvar x= document.getElementById('OneHref');x.href = x.href+'/?hxID='+hxID;alert(x.href);}</script></body></html>");
 maxlen = str0.len+(r->host_end-r->host_start)+r->args.len+str1.len+sizeof(ngx_int_t)+str2.len;
 //b=ngx_create_temp_buf(r->pool,response.len);
 b=ngx_create_temp_buf(r->pool,maxlen);
 if(b == NULL){
 return NGX_HTTP_INTERNAL_SERVER_ERROR;
 }
 ngx_snprintf(b->pos,maxlen,(char *)str0.data,r->host_end,r->args.data,str1.data,&hxID,str2.data);
 ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-log-ngx_func_build_warningPage:");
 fprintf(stderr, "sxx-fpf-ngx_func_build_warningPage:%s",b->pos);
 return NGX_OK;
 }*/
ngx_int_t ipslab_ip_atoi(ngx_str_t str_ip)
{
	ngx_int_t int_ip=-1;
	struct in_addr addr;

 char* char_ip = malloc((str_ip.len+1)*sizeof(char));
 ngx_memcpy(char_ip,str_ip.data,str_ip.len);
 *(char_ip+str_ip.len) ='\0' ;
	    if(inet_aton(char_ip,&addr))
	    {
	        int_ip = ntohl(addr.s_addr);
	    }
	    return int_ip;

}
/*static ngx_int_t ngx_http_ipslab_input_filter(void *data, ssize_t bytes){

	return
}*/
//handle������
static ngx_int_t ngx_http_ipslab_handler(ngx_http_request_t *r) {
	//1.��uri����ȡ��ID��2.��ipΪ�ؼ��ַ���һ�ι����ڴ棬�ڵ��������»��߽ڵ㲻��������䣬��������Ӻ����������µ�ID��
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-ngx_http_ipslab_handler:before ngx_abstract_hxID");
	fprintf(stderr, "sxx-ngx_http_ipslab_handler:before ngx_abstract_hxID");
	u_char* client_ID;
	u_char* server_ID;
	ngx_int_t id_begin_pos=0;
	ngx_int_t id_end_pos=0;
	ngx_int_t clientid_now_len;
	ngx_uint_t ip_int;
	// ngx_str_t tmpstr = ngx_string("?hxID=");
	// ngx_int_t ID_POS_MIN=tmpstr.len;
	ngx_int_t id_pos = ID_POS_MIN - 1;   //url��hxID=�ź��濪ʼ��λ�ã���ʼֵΪ-1.
	ngx_http_ipslab_conf_t *conf;
	ngx_http_ipslab_ctx_t* myctx;

	/*int crv_len;
	 unsigned int nid;
	EC_builtin_curve *curves;
	  crv_len = EC_get_builtin_curves(NULL, 0);
	    curves = (EC_builtin_curve *)malloc(sizeof(EC_builtin_curve) * crv_len);
	    // ��ȡ��Բ�����б�
	    EC_get_builtin_curves(curves, crv_len);
	    // ѡȡһ����Բ����
	    for(int i=0;i<crv_len;i++)
	    {
	    	nid=curves[i].nid;
	      fprintf(stderr,"sxx-fpf i:%d",i);
	      fprintf(stderr,"sxx-fpf nid:%d",nid);
	      fprintf(stderr,"sxx-fpf comment:%s\r\n",curves[i].comment);
	    }*/
ngx_int_t rc;
	//��client_ID �����ڴ沢�������
	client_ID = ngx_palloc(r->pool, ENCRPT_ID_SIZE);
	server_ID = ngx_palloc(r->pool, ENCRPT_ID_SIZE);
	ngx_memset(server_ID,'\0',ENCRPT_ID_SIZE);
	for(int i =0;i<32;i++)
			{
				fprintf(stderr, "sxx-sxx-server_ID:after palloc%c\r\n",server_ID[i]);
				ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
								"sxx-log-ngx_http_mytest_handler sub_location:%c\r\n",
								server_ID[i]);
			}
	server_ID[ENCRPT_ID_SIZE-1] = '\0';
	ngx_abstract_hxID(r, &id_begin_pos,&id_end_pos);
	clientid_now_len =  id_end_pos-id_begin_pos;
	ngx_memcpy(client_ID, r->args.data + id_begin_pos,clientid_now_len);
	client_ID[clientid_now_len] ='\0' ;

	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
			"sxx-ngx_http_ipslab_handler:after ngx_abstract_hxID");
	fprintf(stderr, "sxx-ngx_http_ipslab_handler: after ngx_abstract_hxID");


	//ip_int = ngx_atoi(r->connection->addr_text.data,r->connection->addr_text.len);
	ip_int = ipslab_ip_atoi(r->connection->addr_text);
	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-log-ngx_http_ipslab_handler:ipint %V",&r->connection->addr_text);



	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-log-ngx_http_ipslab_handler:ipint %u",ip_int);
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: ip_int %i",(int)ip_int);


	conf = ngx_http_get_module_main_conf(r, ngx_http_ipslab_module);
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: 667");

	//fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler:node %s",(char*));
	ngx_shmtx_lock(&conf->shpool->mutex);
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: lock shmtx");

	ngx_http_ipslab_lookup(r, conf, ip_int, server_ID); //�������ң���ip�Ĳ���nextID�����������ڱȽϡ�û��ID������¼�¼��������ID
	fprintf(stderr, "sxx-fpf-ngx_http_ipslab_handler: after lookup serverID:%s]",server_ID);
	ngx_shmtx_unlock(&conf->shpool->mutex);



	if (0 == ngx_memcmp(server_ID, client_ID,ENCRPT_ID_SIZE)) {
		fprintf(stderr, "sxx-client_ID == server_ID\r\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-sxx-client_ID:%s, == server_ID:%s\r\n", client_ID,
				server_ID);
		//����http������

		myctx = ngx_http_get_module_ctx(r, ngx_http_ipslab_module);
		// ngx_buf_t *b ;
		if (myctx == NULL) {
			myctx = ngx_palloc(r->pool, sizeof(ngx_http_ipslab_ctx_t));
			if (myctx == NULL) {
				return NGX_ERROR;
			}
			// b = ngx_create_temp_buf(r->pool,50);
			fprintf(stderr, "%s", "I am here");
			myctx->out_ctx = ngx_palloc(r->pool, sizeof(ngx_chain_t));
			/*    myctx->out_ctx->buf=b;
			 myctx->out_ctx->next=NULL;*/
			//�����������õ�ԭʼ����r��
			fprintf(stderr, "%s", "I am here");
			ngx_http_set_ctx(r, myctx, ngx_http_ipslab_module);
		}

		// ngx_http_post_subrequest_t�ṹ������������Ļص��������μ�5.4.1��
		ngx_http_post_subrequest_t *psr = ngx_palloc(r->pool,
				sizeof(ngx_http_post_subrequest_t));
		if (psr == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		//����������ص�����Ϊmytest_subrequest_post_handler
		psr->handler = ipslab_subrequest_post_handler;

		//data��Ϊmyctx�����ģ������ص�mytest_subrequest_post_handler
		//ʱ�����data��������myctx
		psr->data = myctx;

		//�������URIǰ׺��/list��������Ϊ�������˷������������������
		//��/list=s_sh000001������URI������5.6.1����nginx.conf��
		//���õ�������location�е�URI��һ�µ�
		ngx_str_t sub_prefix = ngx_string("/tmpdir");
		ngx_str_t sub_location;

		if (r->args.data == NULL) {
			sub_location.len = sub_prefix.len + r->uri.len;/*******/
			sub_location.data = ngx_palloc(r->pool, sub_location.len);
			ngx_snprintf(sub_location.data, sub_location.len, "%V%V",
					&sub_prefix, &r->uri);
		} else {
			ngx_str_t tmp_args;
			tmp_args.len = id_pos - 5;
			tmp_args.data = ngx_palloc(r->pool, tmp_args.len);
			ngx_memcpy(tmp_args.data, r->args.data, tmp_args.len);

			sub_location.len = sub_prefix.len + r->uri.len + tmp_args.len;/*******/
			sub_location.data = ngx_palloc(r->pool, sub_location.len);
			ngx_snprintf(sub_location.data, sub_location.len, "%V%V%V",
					&sub_prefix, &r->uri, &tmp_args);

		}

		/* ngx_str_t sub_location;
		 sub_location.len =  r->args.len;
		 sub_location.data = ngx_palloc(r->pool, sub_location.len);
		 ngx_snprintf(sub_location.data, sub_location.len,
		 "%V", &r->args);*/

		//sr����������
		ngx_http_request_t *sr;
		//����ngx_http_subrequest������������ֻ�᷵��NGX_OK
		//����NGX_ERROR������NGX_OKʱ��sr���Ѿ��ǺϷ���������ע�⣬����
		//��NGX_HTTP_SUBREQUEST_IN_MEMORY����������upstreamģ�����
		//�η���������Ӧȫ���������������sr->upstream->buffer�ڴ滺������
		fprintf(stderr, "sxx-fpf-ngx_http_mytest_handler sub_location: %s\r\n",
				sub_location.data);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-log-ngx_http_mytest_handler sub_location:%V\r\n",
				sub_location);

		rc = ngx_http_subrequest(r, &sub_location, NULL, &sr, psr,
				NGX_HTTP_SUBREQUEST_IN_MEMORY);
		//8888 sr->upstream->input_filter =ngx_http_ipslab_input_filter;
		//sr->upstream->buffering = 1;
		//sr->upstream->input_filter
		//sr->upstream->bufs.size = ngx_pagesize;
		if (rc != NGX_OK) {
			return NGX_ERROR;
		}

		if (r->out == NULL) {
			/*r->out->buf = ngx_create_temp_buf(r->pool,200);
			 r->out->next = NULL;*/
			fprintf(stderr, "%s",
					"sxx-fpf-ngx_http_mytest_handler r->out->buf== NULL");
		} else {
			fprintf(stderr, "%s",
					"sxx-fpf-ngx_http_mytest_handler  out->buf != null");
		}
		//���뷵��NGX_DONE������ͬupstream
		return NGX_DONE;

		//return NGX_DECLINED;
	} else {
		fprintf(stderr, "sxx-client_ID != server_ID\r\n");
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-sxx-client_ID in s:%s, != server_ID in i:%s\r\n", client_ID,
				server_ID);
		for(int i =0;i<32;i++)
		{
			fprintf(stderr, "sxx-sxx-server_ID:%c\r\n",server_ID[i]);
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
							"sxx-log-ngx_http_mytest_handler server_ID:%c\r\n",
							server_ID[i]);

		}

		ngx_buf_t *b;
		//ngx_func_build_warningPage(b,server_ID,r);
		/*if(b == NULL){
		 return NGX_HTTP_INTERNAL_SERVER_ERROR;
		 }*/
		//ngx_memcpy(b->pos,response.data,response.len);
		ngx_int_t maxlen;
		ngx_str_t str0 =
						ngx_string(
								"<html>\r\n<body>\r\n<h1>��֤ҳ��</h1>\r\n");
		ngx_str_t str1 = ngx_string(
						"<script src=\"https://cdnjs.cloudflare.com/ajax/libs/blueimp-md5/2.10.0/js/md5.min.js\"></script>");
		ngx_str_t str2 = ngx_string("<a id = 'OneHref' href= '");

		//ngx_str_t tmp_host = ngx_string("127.0.0.1:80");
		ngx_str_t str4 =
						ngx_string(
								"' onclick = 'doSomething()'>TRY AGAIN</a>\r\n<script type='text/javascript'>\r\n var hxID = md5(\"");

		//str5 = hxID;
		ngx_str_t str6 =
						ngx_string(
								"\");\r\n function doSomething()\r\n{\r\n var x= document.getElementById('OneHref');\r\nx.href += '?hxID='+hxID;\r\nalert(x.href);\r\n}</script>\r\n</body>\r\n</html>\r\n");

		//ngx_str_t str3 = ngx_string("+1;\r\n function doSomething()\r\n{\r\n var x= document.getElementById('OneHref');x.href = '/?hxID='+hxID;alert(x.href);}</script></body></html>");
		//maxlen = str0.len+tmp_host.len+r->args.len+str1.len+str2.len+str3.len;
		//maxlen = str0.len+r->uri.len+str1.len+sizeof(ngx_int_t)+str3.len;
		//һ������ID��ngx_int_tռ���ֽ�Ҫ����char��
		maxlen = str0.len + str1.len + str2.len+r->uri.len + str4.len +ENCRPT_ID_SIZE +str6.len;

		//maxlen = str0.len+(r->host_end-r->host_start)+r->args.len+str1.len+sizeof(ngx_int_t)+str2.len;
		//b=ngx_create_temp_buf(r->pool,response.len);
		b = ngx_create_temp_buf(r->pool, maxlen);
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}
		//ngx_snprintf(b->pos,maxlen,"%V%V%V%V%V",&str0,&tmp_host,&str1,&str2,&str3);
		//ngx_snprintf(b->pos,maxlen,"%V%V%V%V%i%V",&str0,&tmp_host,&r->uri,&str1,server_ID,&str3);
		fprintf(stderr,"sxx-spf-ngx_http_ipslab_handler before snprintf server_ID:%s]",server_ID);
		ngx_snprintf(b->pos, maxlen, "%V%V%V%V%V%s%V", &str0,&str1,&str2, &r->uri,&str4,
				server_ID, &str6);

		/*ngx_str_t response = ngx_string("error");
		 ngx_memcpy(b->pos,response.len,response.data);
		 b->last = b->pos+response.len;*/
		b->last = b->pos + maxlen;

		b->last_buf = 1;
		fprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->args:%s",
				(char *) r->args.data);
		fprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->uri:%s",
				(char *) r->uri.data);
		fprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->host_end:%s",
				(char *) r->host_start);    	//r->host_end - r->host_start,
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-log-ngx_func_build_warningPage:r->args:%V", r->args);
		ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
				"sxx-log-ngx_func_build_warningPage:r->uri:%V", r->uri);
		//ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-log-ngx_func_build_warningPage:r->host_end:%s",r->host_end - r->host_start,r->host_start);
		if (r->host_end - r->host_start == 0)
			ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
					"sxx-log-ngx_func_build_warningPage: == 0"); //,r->connection->addr_text);

		//ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-log-ngx_func_build_warningPage:r->host->value:%V",r->host->value);//r->headers_in.server.data);
		//ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-log-ngx_func_build_warningPage:r->host->value:%V",r->headers_in->server);//r->headers_in.server.data);

		/*ngx_sprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->args:%V",r->args);
		 ngx_sprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->uri:%V",r->uri);
		 ngx_sprintf(stderr, "sxx-fpf-ngx_func_build_warningPager->host_end:%s",r->host_end - r->host_start,r->host_start);*/

		//fprintf(stderr, "sxx-fpf-ngx_func_build_warningPage:%s",b->pos);
		//	ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0, "sxx-log-ngx_func_build_warningPage:");
		ngx_chain_t out;
		out.buf = b;
		out.next = NULL;
		return ngx_http_output_filter(r, &out);
	}
	return NGX_OK;
}

