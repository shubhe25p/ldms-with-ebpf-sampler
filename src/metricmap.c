#include <stdio.h>
#include <unistd.h>
#include <sys/errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>
#include "metricmap.h"

/*****************************************************************************
 * This is a demonstration library with the ability to take the hwloc heirarchical
 * node and below level information and the ldms data information and build an
 * SNMP-inspired naming convention for component and variable data for the combination
 * of the two. This library also provides calls for ldms <-> SNMP naming convention
 * conversion. This library also currently supports instantaneous storage and retrieval
 * of the data values. It NOT intended to be the final structure, but to serve as
 * an initial workable test code upon which we can determine requirements that
 * we want in our eventual goal. This does NOT support upper level connectivity
 * amongst the machines.
 ****************************************************************************/

//NOTE: that Machine0 will be everyhosts base host, with the actual machines in a separate array.
//NOTE: dottedstring as a parameter means the full string text in the oid

//FIXME: assumes hostname/setname/metricname. will want to support multiply slashed metricnames

//TODO: this is not the final data structure. tradeoffs of hash table vs walking the structure for large numbers.
//NOTE: have put in hash table for hosts. have realized problem in naming convention and going back and
//forth from numerical OID to namestring OID if there are multiple types of components at the same level.
//START HERE...


//TODO: currently this is set up for one architecture in common to many machines. Extend this to
//support multiple architectures that will be in common for sets of machines.

//NOTE: Currently the metric UIDS are assigned in the order in which they appear in the
//metric data files as they are processed, thus they may change from run to run. Only the
//machines support user-defined Lvals (which can then be fixed from run-to-run). This
//is a deliberate choice as machine Lvals can then be nids and then low, contiguous numerical
//values will be used for metrics when only a few data vals are being collected


int numlevels = 0;
int numsets = 0;
int numhosts = 0;
int treesize = 0;
int numknownassoc = 0;

int getHwlocAssoc( char *assoc ){
  if (!strncmp(assoc, "PU", MAXSHORTNAME)){
    return PU;
  }
  if (!strncmp(assoc, "Machine", MAXSHORTNAME)){
    return Machine;
  }
  if (!strncmp(assoc, "Socket", MAXSHORTNAME)){
    return Socket;
  }
  if (!strncmp(assoc, "NUMANode", MAXSHORTNAME)){
    return NUMANode;
  }
  if (!strncmp(assoc, "L3Cache", MAXSHORTNAME)){
    return L3Cache;
  }
  if (!strncmp(assoc, "L2Cache", MAXSHORTNAME)){
    return L2Cache;
  }
  if (!strncmp(assoc, "L1Cache", MAXSHORTNAME)){
    return L1Cache;
  }
  return 0;
}


int cleanup(){
  //free the metrics thru hwloc because there are metrics via hwloc that are not ldms metrics
  //need only free the instances once
  int i, j, k;
  for (i = numlevels-1; i > numlevels; i--){
    for (j = 0; j < hwloc[i].numinstances; j++){
      for (k = 0; k < hwloc[i].instances[j]->nummetrics; k++){
	free(hwloc[i].instances[j]->metrics[k]);
      }
      free(hwloc[i].instances[j]);
    }
  }

  //all other structs are not dynamically allocated

  g_hash_table_destroy(hostnameToHostOID);
  g_hash_table_destroy(hostOIDToHostIndex);
  return 0;
}

static void printStrToStrHash(gpointer key, gpointer value, gpointer user_data){
  printf("<%s><%s>\n", (char*)key, (char*)value);
}

static void printStrToIntHash(gpointer key, gpointer value, gpointer user_data){
  printf("<%s><%d>\n", (char*)key, *((int*)value));
}

void printHostnameToHostOIDHash(){
  g_hash_table_foreach(hostnameToHostOID, printStrToStrHash, NULL);
}

void printHostOIDToHostIndexHash(){
  g_hash_table_foreach(hostOIDToHostIndex, printStrToIntHash, NULL);
}


int getLDMSName(struct MetricInfo* mi, int hostoid, char* hostname, char* setname, char* metricname){

  if (mi == NULL){
    printf("Error: NULL input metric\n");
    return -1;
  }

  hostname[0] = '\0';
  setname[0] = '\0';
  metricname[0] = '\0';


  char hostoidc[5];
  snprintf(hostoidc,5,"%d",hostoid);
  
  int* hostidx = g_hash_table_lookup(hostOIDToHostIndex,hostoidc);
  if (hostidx == NULL){
    printf("Error: no host <%d>\n", hostoid);
    return -1;
  }
  snprintf(hostname, MAXLONGNAME, "%s", hosts[*hostidx].hostname);

  if (mi->ldmsparent == NULL){
    //may not be an ldms metric
    //    printf("Error: bad parent for metric <%s>\n", mi->ldmsname);
    return -1;
  }
  snprintf(setname, MAXLONGNAME, "%s", mi->ldmsparent->setname);
  snprintf(metricname, MAXLONGNAME, "%s", mi->ldmsname);

  return 0;
}

int getMetricInfo(char* oid_orig, struct MetricInfo** mi, int* idx, int dottedstring){ 
  //return the metric info and the index
  //oid needs to have the form ComponentOID/ComponentOIDString.METRICCATAGORYUID/METRICCATAGORYNAME.MIBmetricUID/MIBmetricname

  char oid[MAXBUFSIZE];
  snprintf(oid,MAXBUFSIZE,"%s",oid_orig);

  if ((mi == NULL) || (*mi != NULL)){
    printf("Error: sending erroneous metric info arg\n");
    return -1;
  }

  //  printf("considering <%s>\n",oid);

  int i;
  int found = -1;
  int val;
  int hostidx = -1;
  int count = 0;

  char seg[MAXHWLOCLEVELS+5][MAXLONGNAME];
  char *p = strtok(oid, ".\n");
  while (p!= NULL){
    snprintf(seg[count++],MAXLONGNAME, "%s",p);
    p = strtok(NULL, ".\n");
  }
  if (count < 3){
    printf("Error: bad oid <%s> num segs\n", oid);
    return -1;  
  }

  if (dottedstring){
    //string will start with MachineNum
    if ((strncmp(seg[0],"Machine", strlen("Machine")) != 0) || (strlen(seg[0]) < (strlen("Machine")+1))){
      printf("Error: bad oid string assoc <%s>\n", oid_orig);
      return -1;
    }
    char* p = &(seg[0][strlen("Machine")]);
    val = atoi(p);
    //write over seg 0 with the val
    snprintf(seg[0], 5, "%d", val);
  } 

  for (i = 0; i < numhosts;i++){
    if (!strcmp(hosts[i].Lval,seg[0])){
      hostidx = i;
      break;
    }
  }
  if (hostidx == -1){
    printf("Error: bad host oid <%s>\n",seg[0]);
    return -1;
  }

  *idx = hostidx;
  
  int levelnum = count-2-1; //level (index) of the component
  int level = 0;

  //  printf("<%s> count %d levelnum %d\n", oid_orig, count, levelnum);
  struct Linfo *li = hwloc[0].instances[0];
  while (li != NULL && level < levelnum){
    found = -1;
    if (!dottedstring){
      for (i = 0; i < li->numchildren; i++){
	if (!strcmp(li->children[i]->Lval, seg[level+1])){
	  found = 1;
	  li =  li->children[i];
	  break;
	}
      }
      if (found == -1){
	printf("Error: bad oid <%s> no component (level = %d)\n", oid_orig, level);
	return -1;
      }
    } else {
      //have to extract the assoc. 
      char assoc[MAXSHORTNAME];
      found = -1;
      for (i = 0; i < numknownassoc; i++){
	if (!strncmp(seg[level+1],knownassoc[i], strlen(knownassoc[i]))){
	  found = i;
	  snprintf(assoc,MAXSHORTNAME,"%s",knownassoc[i]);
	  break;
	}
      }
      if (found == -1){
	printf("Error: bad seg <%s>\n", seg[level+1]);
	return -1;
	break;
      }
      found = -1;
      char* p = &(seg[level+1][strlen(assoc)]);
      val = atoi(p);
      for (i = 0; i < li-> numchildren; i++){
	if (!strcmp(li->children[i]->assoc,assoc) && atoi(li->children[i]->Lval) == val){
	  found = 1;
	  li = li->children[i];
	  break;
	}
      }
      if (found == -1){
	printf("Error: bad oid <%s> no component (level = %d)\n", oid_orig, level);
	return -1;
      }
    }
    level++;
  }
  if (li == NULL){
    printf("Error: bad oid <%s> no component (levelnum = %d)\n", oid_orig, levelnum);
    return -1;
  }

  if (!dottedstring){
    if (atoi(seg[count-2]) != MIBMETRICCATAGORYUID){
      printf("Error: bad oid <%s> catagory num\n", oid_orig);
      return -1;
    }
  } else {
    if (strcmp(seg[count-2], MIBMETRICCATAGORYNAME) != 0 ){
      printf("Error: bad oid <%s> catagory name <%s>\n", oid_orig, seg[count-2]);
      return -1;
    }
  }

  if (!dottedstring){
    for (i = 0; i < li->nummetrics; i++){
      if (li->metrics[i]->MIBmetricUID == atoi(seg[count-1])){
	*mi = li->metrics[i];
	break;
      }
    }
  } else {
    for (i = 0; i < li->nummetrics; i++){
      if (!strcmp(li->metrics[i]->MIBmetricname, seg[count-1])){
	*mi = li->metrics[i];
	break;
      }
    }
  }
  
  if (*mi == NULL){
    printf("Error: bad oid <%s> <%s>(no metric) \n", oid_orig, seg[count-1]);
    return -1;
  }

  return 0;

}


int OIDToLDMS(char* oid_orig, char* hostname, char* setname, char* metricname, int dottedstring){

  struct MetricInfo* mi = NULL; 
  int idx;
  int val;

  int rc = getMetricInfo( oid_orig, &mi, &idx, dottedstring);
  if (rc != 0){
    printf("WARNING: No metric info for <%s>\n", oid_orig);
    return -1;
  }
  if (idx < 0 || idx >= numhosts){
    printf("ERROR: bad host num <%d>\n", idx);
    return -1;
  }
    
  val = atoi(hosts[idx].Lval);

  return getLDMSName(mi, val, hostname,setname, metricname);
}


int LDMSToOID(char *hostname, char* setname, char* metricname, char* hwlocname, int dottedstring){

  hwlocname[0] = '\0';
  if ((strlen(hostname) == 0) || (strlen(setname) == 0) || (strlen(metricname) == 0)){
    return -1;
  }

  //given setname metricname get the hwlocname
  int i;

  int hostoid = -1;
  char* p = g_hash_table_lookup(hostnameToHostOID,hostname);
  if (p == NULL){
    printf("Error: no hostx <%s>\n", hostname);
    return -1;
  }
  hostoid = atoi(p);
  if (hostoid < 0){
    printf("Error: no hostx <%s>\n", hostname);
    return -1;
  }

  int setnum = -1;
  for (i = 0; i < numsets; i++){
    if (!strcmp(sets[i].setname,setname)){
      setnum = i;
      break;
    }
  }
  if (setnum == -1){
    //    printf("Error: dont have set <%s>\n",setname);
    return -1;
  }

  //process this metric
  for (i = 0; i < sets[setnum].nummetrics; i++){
    if (!(strcmp(sets[setnum].metrics[i]->ldmsname,metricname))){
      return getMetricOID(sets[setnum].metrics[i], hostoid, hwlocname, dottedstring);
    }
  }

  //  printf("Error: dont have metric <%s>\n",metricname);
  return -1;
};


int setMetricValueFromOID(char* oid, unsigned long val, int dottedstring){
  struct MetricInfo *mi = NULL;  int idx = -1;


  int rc = getMetricInfo(oid, &mi, &idx, dottedstring); 
  if (rc != 0){
    printf("Error: no metric for oid <%s>\n", oid);
    return -1;
  }

  if (idx >= MAXHOSTS || idx < 0){
    printf("Error: index out of range <%d>\n",idx);
    exit (-1);
  }
  if (mi == NULL){
    printf("Error: no metric for <%s> (idx = %d)\n", oid, idx);
    return -1;
  }
  //  printf("should be setting val for <%s> <%lu> <%d>\n",mi->MIBmetricname, val, idx);

  mi->values[idx] = val;
  return 1;
};

int setMetricValueFromLDMS(char* hostname, char* setname, char* metricname, unsigned long val){

  if ((strlen(hostname) == 0) || (strlen(setname) == 0) || (strlen(metricname) == 0)){
    return -1;
  }

  int i;

  char* hostoid = g_hash_table_lookup(hostnameToHostOID, hostname);
  if (hostoid == NULL){
    printf("Error: no host <%s>\n", hostname);
    return -1;
  }
  int* hostx = g_hash_table_lookup(hostOIDToHostIndex,hostoid);
  if (hostx == NULL || *hostx < 0){
    printf("Error: no host <%s>\n", hostname);
    return -1;
  }

  int setnum = -1;
  for (i = 0; i < numsets; i++){
    if (!strcmp(sets[i].setname,setname)){
      setnum = i;
      break;
    }
  }
  if (setnum == -1){
    //    printf("Error: dont have set <%s>\n",setname);
    return -1;
  }

  for (i = 0; i < sets[setnum].nummetrics; i++){
    if (!(strcmp(sets[setnum].metrics[i]->ldmsname,metricname))){
      sets[setnum].metrics[i]->values[*hostx] = val;
      return 0;
    }
  }

  printf("Error: dont have metric <%s>\n",metricname);
  return -1;

};


int getMetricValueFromOID(char* oid, unsigned long *val, int dottedstring){
  struct MetricInfo *mi = NULL;
  int idx = -1;

  int rc = getMetricInfo(oid, &mi, &idx, dottedstring);
  if (rc != 0){
    printf("Error: no metric for oid <%s>\n", oid);
    return -1;
  }

  if (idx >= MAXHOSTS || idx < 0){
    printf("Error: index out of range <%d>\n",idx);
    exit (-1);
  }
  if (mi == NULL){
    printf("Error: no metric for <%s> (idx = %d)\n", oid, idx);
    return -1;
  }


  *val = mi->values[idx];
  return 0;

};


void printMetric(struct MetricInfo* mi, int hostoid, char* prefix){
  if (mi == NULL){
    return;
  }

  char oid[MAXLONGNAME], oidString[MAXLONGNAME];
  oid[0] = '\0';
  oidString[0] = '\0';
  int rc = getMetricOID(mi, hostoid, oid, 0);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }
  rc = getMetricOID(mi, hostoid, oidString, 1);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }

  char hostname[MAXLONGNAME];
  char setname[MAXLONGNAME];
  char metricname[MAXLONGNAME];
  char longldmsname[MAXLONGNAME];


  //  if (OIDToLDMS(oid, hostname, setname, metricname, 0) == 0){
  if (getLDMSName(mi, hostoid, hostname, setname, metricname) == 0){
    snprintf(longldmsname,MAXLONGNAME, "%s/%s/%s",hostname,setname,metricname);
  } else {
    snprintf(longldmsname, MAXLONGNAME, "%s", mi->ldmsname); //should be NONE
  }

  char hostoidc[5];
  snprintf(hostoidc,5,"%d",hostoid);
  int* hostx = g_hash_table_lookup(hostOIDToHostIndex,hostoidc);
  if (hostx == NULL || *hostx < 0){
    printf("Error: no host <%s>\n", hostname);
    exit(-1);
  }

  printf("%s %-120s %-30s (ldmsname: %s) (value %lu) \n", prefix, oidString, oid, longldmsname, mi->values[*hostx]);

}


void printComponent(struct Linfo* tr, int hostoid, char* prefix){

  if (tr == NULL){
    return;
  }

  char oid[MAXLONGNAME], oidString[MAXLONGNAME];
  oid[0] = '\0';
  oidString[0] = '\0';

  int rc = getComponentOID(tr, hostoid, oid, 0);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }
  rc = getComponentOID(tr, hostoid, oidString, 1);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }

  if (!strcmp(tr->assoc,"Machine")){
    char hostoidc[5];
    snprintf(hostoidc,5,"%d",hostoid);
    int* hostx = g_hash_table_lookup(hostOIDToHostIndex,hostoidc);
    if (hostx == NULL || (*hostx) < 0){
      printf("Error: no host <%d>\n", hostoid);
      exit (-1);
    }
    printf("%s (%-30s) %-120s %-30s\n",
	   prefix, hosts[*hostx].hostname, oidString, oid);
    return;
  } else {
    printf("%s %-120s %-30s\n", prefix, oidString, oid);
  }
};


void printComponents(int printMetrics){
  int i,j,k;
  printf("\n\nComponents:\n");
  //first level print all the machines:
  if (numhosts < 1){
    printf("WARNING: no hosts!\n");
  } else {
    printf("%s:\n", hwloc[0].instances[0]->assoc);
    for (i = 0; i < numhosts; i++){
      printComponent(hwloc[0].instances[0], atoi(hosts[i].Lval),"\t");
      if (printMetrics){
	printf("\t\tMetrics:\n");
	for (k = 0; k < hwloc[0].instances[0]->nummetrics; k++){
	  printMetric(hwloc[0].instances[0]->metrics[k], atoi(hosts[i].Lval),"\t\t"); 	  //there may be some that arent LDMS metrics
	}
      }
    }
  }
  printf("Generic subcomponents:\n");
  for (i = 1; i < numlevels; i++){
    printf("%s:\n", hwloc[i].assoc);
    for (j = 0; j < hwloc[i].numinstances; j++){
      //use the first legitmate host Lval
      printComponent(hwloc[i].instances[j], 
		     (numhosts > 0 ? atoi(hosts[0].Lval): atoi(hwloc[0].instances[0]->Lval)),
		      "\t");
      if (printMetrics){
	printf("\t\tMetrics:\n");
	for (k = 0; k < hwloc[i].instances[j]->nummetrics; k++){
	  printMetric(hwloc[i].instances[j]->metrics[k],
		      (numhosts >0 ? atoi(hosts[0].Lval): atoi(hwloc[0].instances[0]->Lval)),
		       "\t\t"); 	  //there may be some that arent LDMS metrics
	}
      }
    }
  }
  printf("\n");
}


void printTreeGuts(struct Linfo* tr, int hostoid){
  int i;

  if (tr == NULL){
    return;
  }

  char oid[MAXLONGNAME], oidString[MAXLONGNAME];
  oid[0] = '\0';
  oidString[0] = '\0';
  int rc = getComponentOID(tr, hostoid, oid, 1);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }
  rc = getComponentOID(tr, hostoid, oidString, 0);
  if (rc < 0){
    printf("Error: bad oid!\n");
    exit (-1);
  }
  printf("\t%-120s %-30s (%d direct children) (%d metrics)\n", oidString, oid, tr->numchildren, tr->nummetrics);
  for (i = 0; i < tr->nummetrics; i++){
    printMetric(tr->metrics[i], hostoid, "\t");
  }

  for (i = 0; i < tr->numchildren; i++){
    printTreeGuts(tr->children[i], hostoid);
  }
}


void printTree(int hostoid){
  //if hostoid < 0 print all otherwise print one
  int i;

  printf("\n\nTrees:\n");
  if (numhosts < 1){
    printf("WARNING: no hosts!\n");
    printf("%s (%s):\n", hwloc[0].instances[0]->assoc, "NONAME");
    printTreeGuts(hwloc[0].instances[0], atoi(hwloc[0].instances[0]->Lval));
    return;
  }

  if (hostoid < 0){
    for (i = 0; i < numhosts; i++){
      printf("%s (%s):\n", hwloc[0].instances[0]->assoc, hosts[i].hostname);
      printTreeGuts(hwloc[0].instances[0], atoi(hosts[i].Lval));
    }
    return;
  } else {
    for (i = 0; i < numhosts; i++){
      if (atoi(hosts[i].Lval) == hostoid){
	printf("%s (%s):\n", hwloc[0].instances[0]->assoc, hosts[i].hostname);
	printTreeGuts(hwloc[0].instances[0], hostoid);
	return;
      }
    }
    printf("WARNING: no host <%d>\n", hostoid);
  }

  return;
}

int getMetricOID(struct MetricInfo* mi, unsigned int hostoid, char* str, int dottedstring){
  char temp[MAXLONGNAME];
  str[0] = '\0';
  temp[0] = '\0';

  if (mi == NULL){
    printf("Error: passed in a null metric\n");
    return -1;
  }

  if (mi->instance == NULL){
    printf("Error: no component for metric <%s>\n",mi->MIBmetricname);
    return -1;
  }

  int rc = getComponentOID(mi->instance, hostoid, temp, dottedstring);
  if (rc < 0){
    printf("Error: cant get component oid for metric <%s>\n", mi->MIBmetricname);
    return -1;
  }
  if (strlen(temp) == 0){
    printf("Error: cant get component oid for metric <%s>\n", mi->MIBmetricname);
    return -1;
  }
  
  if (!dottedstring){
    snprintf(str, MAXLONGNAME, "%s.%d.%d",temp,MIBMETRICCATAGORYUID,mi->MIBmetricUID);
  } else {
    snprintf(str, MAXLONGNAME, "%s.%s.%s",temp,MIBMETRICCATAGORYNAME,mi->MIBmetricname);
  }
  return 0;
}

int getComponentOID(struct Linfo* linfo, unsigned int hostoid, char* str, int dottedstring){
  //WARNING: be sure str[0] = '\0' before you call this
  //FIXME: test to be sure str[0] was cleared before this call
  int i;

  if (linfo == NULL){
    printf("Error: passed in a null component\n");
    return -1;
  }

  //check if top of the tree
  if (linfo->parent == NULL){
    if (!strcmp(linfo->assoc,"Machine")){
      //print the actual component of interest

      //make sure this is a valid hostid
      for (i = 0; i < numhosts; i++){
	if (atoi(hosts[i].Lval) == hostoid){
	  char temp[MAXLONGNAME];
	  if (!dottedstring){
	    if (strlen(str) > 0){
	      snprintf(temp, MAXLONGNAME, "%d.%s", hostoid, str);
	    } else {
	      snprintf(temp, MAXLONGNAME, "%d", hostoid);
	    }
	  } else {
	    if (strlen(str) > 0){
	      snprintf(temp, MAXLONGNAME, "%s%d.%s", linfo->assoc, hostoid, str);
	    } else {
	      snprintf(temp, MAXLONGNAME, "%s%d", linfo->assoc, hostoid);
	    }
	  }
	  snprintf(str, MAXLONGNAME, temp);
	  return 1;
	}
      }
      printf("Error: no host <%d>\n", hostoid);
      return -1;
    } else {
      printf("Error: bad tree (top component <%s>)!\n", linfo->assoc);
      return -1;
    }
  }

  //otherwise add myself
  char temp[MAXLONGNAME];
  if (!dottedstring){
    if (strlen(str) > 0){
      snprintf(temp, MAXLONGNAME, "%s.%s", linfo->Lval, str);
    } else {
      snprintf(temp, MAXLONGNAME, "%s", linfo->Lval);
    }
  } else {
    if (strlen(str) > 0){
      snprintf(temp, MAXLONGNAME, "%s%s.%s", linfo->assoc, linfo->Lval, str);
    } else {
      snprintf(temp, MAXLONGNAME, "%s%s", linfo->assoc, linfo->Lval);
    }
  }
  snprintf(str, MAXLONGNAME, temp);

  return getComponentOID(linfo->parent, hostoid, str, dottedstring);      

}

int getInstanceMetricNames(char* orig, char* Lval, char* ldmsname, char* hwlocname){
  //the metric name MUST have an LVAL to replace, expect for where there is only 1 instance of that component involved
  //eg the metricname might be CPU(LVAL)_user_raw -> ldmsname of CPU3_user_raw and hwlocname of CPU_user_raw
  //dont currently have a good way to do functions of that

  snprintf(ldmsname, MAXSHORTNAME, "%s", orig);
  snprintf(hwlocname, MAXSHORTNAME, "%s", orig);
  char *p;
  char buf[MAXSHORTNAME];

  //  printf("considering <%s>\n", orig);

  //FIXME: this has not yet been tested for multiple replacements
  p = strstr(ldmsname, LVALPLACEHOLDER);
  while ( p != NULL){
    strncpy(buf, ldmsname, p-ldmsname);
    buf[p-ldmsname] = '\0';
    sprintf(buf+(p-ldmsname), "%s%s", Lval, p+strlen(LVALPLACEHOLDER));

    strncpy(ldmsname, buf, strlen(buf));
    ldmsname[strlen(buf)] = '\0';
    p = strstr(ldmsname, LVALPLACEHOLDER);
  }

  //  printf("considering <%s>\n", orig);
  p = strstr(hwlocname, LVALPLACEHOLDER);
  while ( p != NULL){
    strncpy(buf, hwlocname, p-hwlocname);
    buf[p-hwlocname] = '\0';
    sprintf(buf+(p-hwlocname), "%s", p+strlen(LVALPLACEHOLDER));

    strncpy(hwlocname, buf, strlen(buf));
    hwlocname[strlen(buf)] = '\0';
    p = strstr(hwlocname, LVALPLACEHOLDER);
  }

  return 0;
}


int parseLDMSData(char* inputfile){
  //user metric data is in a file.
  //first line of the file is the hwloc component type
  //all subsequent lines are ldms setname/metricname (no hostname, these will be common to all hosts)

  //FIXME: need a way for this to add all the metrics of a set without having to put them in the file
  //or have it invoke ldms_ls to get them...

  //FIXME: check for repeats

  //if a line starts with # it will be skipped
  char buf[MAXBUFSIZE];
  char tempbuf[MAXBUFSIZE];
  char assoc[MAXSHORTNAME]; 
  int haveassoc = 0;
  char setname[MAXLONGNAME];
  char metricname[MAXSHORTNAME];
  int comptypenum = -1;

  int numVals = 0;
  int i;
  int setnum = -1;

  //  printf("Parsing ldmsdata file <%s>\n", inputfile);

  FILE *fp = fopen(inputfile, "r");
  if (fp == NULL){
    printf("Error: Can't open metric data file. exiting.\n");
    exit (-1);
  }

  while (fgets(tempbuf, (MAXBUFSIZE-1), fp) != NULL){
    int n =  sscanf(tempbuf,"%s",buf); //remove whitespace
    if (n != 1){
      continue;
    }
    if (buf[0] == '#'){ //its a comment
      continue;
    }
    if (haveassoc == 0){
      //      printf("checking component <%s>\n", buf);
      sscanf(buf, "%s", assoc);
      if (strlen(assoc) == 0){
	continue;
      } 
      comptypenum = -1;
      for (i = 0; i < numlevels; i++){
	if (!strcmp(hwloc[i].assoc, assoc)){
	  comptypenum = i;
	  break;
	}
      }
      if (comptypenum == -1){
	printf("Error: dont know assoc <%s>\n", assoc);
	exit (-1);
      }
      haveassoc = 1 ;
    } else {
      if (buf[0] == '#'){ //its a comment
	continue;
      }
      char *p  = strstr(buf,"/"); //FIXME: assume this is setname/metricname
      if (p == NULL){
	continue;
      }
      strncpy(metricname, p+1, strlen(p));
      metricname[strlen(p)] = '\0';
      strncpy(setname, buf, strlen(buf)-strlen(p));
      setname[strlen(buf)-strlen(p)] = '\0';
      //      printf("<%s><%s>\n",setname, metricname);

      setnum = -1;
      for (i = 0; i < numsets; i++){
	if (!strcmp(sets[i].setname,setname)){
	  setnum = i;
	}
      }

      if (setnum == -1){
	strncpy(sets[numsets].setname,setname,MAXLONGNAME);
	sets[numsets].nummetrics = 0;
	setnum = numsets;
	numsets++;
      }

      for (i = 0; i < hwloc[comptypenum].numinstances; i++){
	char ldmsname[MAXSHORTNAME];
	char hwlocname[MAXSHORTNAME];
	int rc = getInstanceMetricNames(metricname, hwloc[comptypenum].instances[i]->Lval, ldmsname, hwlocname);
	if (rc != 0){
	  printf("Error: Cannot parse the metric regex. Exiting\n");
	  exit (-1);
	}
	//with the current constraints, GUARENTEED that each InstanceLDMSName will be unique and result in a new metric
	//that is, for example, cpu_util on the node is one metric, assoc with the node while
	//cpu_util for each core is each a different metric, assoc with the node
	//a metric can only be associated with a single instance.
	struct MetricInfo* mi = (struct MetricInfo*)malloc(sizeof(struct MetricInfo));
	snprintf(mi->ldmsname,MAXSHORTNAME,"%s",ldmsname);
	snprintf(mi->MIBmetricname,MAXSHORTNAME,"%s",hwlocname);

	//update the hw structs
	struct Linfo* li = hwloc[comptypenum].instances[i]; 
	li->metrics[li->nummetrics] = mi;
	mi->MIBmetricUID = li->nummetrics++;
	if (li->nummetrics >= MAXMETRICSPERCOMPONENT){
	  printf("Error: too many metrics  with <%s>\n", hwlocname);
	  exit(-1);
	}
	mi->instance = li;
	//no values yet

	//update the ldms structs
	sets[setnum].metrics[sets[setnum].nummetrics++] = mi;
	if (sets[setnum].nummetrics >= MAXMETRICSPERSET){
	  printf("Error: too many metrics for <%s> (%d)\n", sets[setnum].setname,sets[setnum].nummetrics);
	  for (i = 0; i < sets[setnum].nummetrics-1; i++){
	    printf("\t<%s>\n", sets[setnum].metrics[i]->ldmsname);
	  }
	  exit(-1);
	}
	mi->ldmsparent = &sets[setnum];

	//	printf("adding LDMS metric\n");
	//	printMetric(mi,1);

	numVals++;
      }
    }
  } //while
  fclose(fp);

  return numVals;
} 



int parse_line(char* lbuf, char* comp_name, int* Lval, int* Pval, char keys[MAXATTR][MAXSHORTNAME], int* attr, int* numAttr){
  enum hwlocAssoc assoc;
  *Lval = -1; 
  *Pval = -1;
  *numAttr = 0;
  int minindex = 0;
  char* ptr;

  //  printf("Raw line <%s>\n",lbuf);
  while(lbuf[minindex] == ' ') {   //strip any leading whitespace
    minindex++;
  }
  ptr = lbuf+minindex;
  if (ptr[0] == '\n'){ //skip blank lines
    return -1;
  }
  //split into the header and the attributes
  char header[MAXBUFSIZE];
  char attrs[MAXBUFSIZE];
  int len = strcspn(ptr, "(");
  strncpy(header, ptr, len);
  header[len] = '\0';
  if (len == strlen(ptr)){
    attrs[0] = '\0';
  } else {
    strncpy(attrs, ptr+len+1, strlen(ptr)-len-1);
    attrs[strlen(ptr)-len-2] = '\0'; //strip the newline
  }

  //  printf("\n\nsplitline header <%s>\n", header);
  //  printf("splitline attrs <%s>\n", attrs);

  //parse header - comptype and optional Lval
  len = strcspn(header, " ");
  strncpy(comp_name, header, len);
  comp_name[len] = '\0';
  assoc = getHwlocAssoc(comp_name);
  if (assoc < 0){ //we dont care about this component
    return -1; 
  }
  ptr = header+len+1;
  if (ptr[0] == 'L' && ptr[1] == '#'){
    *Lval = atoi(ptr+2); //this will handle any extra whitespace
  }

  //parse attrs - optional Pval and key value pairs
  if (attrs[0] == 'P' && attrs[1] == '#'){
    *Pval = atoi(attrs+2);
    len = strcspn(attrs, " ");
    ptr = attrs+len+1;
  } else {
    ptr = attrs;
  }

  //now key-value pairs.
  char* pch;
  int key = 1;
  pch = strtok(ptr, "=)");
  while (pch != NULL){
    if (key){
      //strip any leading whitespace
      minindex = 0;
      while(pch[minindex] == ' '){
	minindex++;
      }
      strncpy(keys[*numAttr],pch+minindex,strlen(pch)-minindex);
      keys[*numAttr][strlen(pch)] = '\0';

      //some name changes
      switch (assoc) {
      case L3Cache:
      case L2Cache:
      case L1Cache:
	if (!strcmp(keys[*numAttr], "size")){
	  strcpy(keys[*numAttr], "cache_size");
	} else if (!strcmp(keys[*numAttr], "linesize")){
	  strcpy(keys[*numAttr], "cache_linesize");
	} else if (!strcmp(keys[*numAttr], "ways")){
	  strcpy(keys[*numAttr], "cache_ways");
	} 
	break;
      case Machine:
      case Socket:
      case NUMANode:
	if (!strcmp(keys[*numAttr], "total")){
	  strcpy(keys[*numAttr], "mem_total");
	} else if (!strcmp(keys[*numAttr], "local")){
	  strcpy(keys[*numAttr], "mem_local");
	} 
	break;
      default:
	;
      }

      key = 0;
      pch = strtok(NULL," )");
    } else {
      //its the value. no good way to handle partial names
      if (pch[0] == '\"'){ //wont be a number
	pch = strtok(NULL,"\""); //each the rest
      } else {
	char *endptr;
	long val;
	val  = strtol(pch, &endptr, 10);
	if (endptr != pch){
	  attr[*numAttr] = (int) val;
	  //	  printf("adding <%s> <%d> <%d>\n", keys[*numAttr], *numAttr, attr[*numAttr]);
	  (*numAttr)++;
	}
      }
      key = 1;
      pch = strtok(NULL,"=)");
    } // else (value)
  }

  //special cases
  switch(assoc){
  case Machine:
    *Lval = 0;
    break;
  default:
    break;
  }

  return 0;
}

void addComponent(char* hwlocAssocStr, int Lval, int Pval, char keys[MAXATTR][MAXSHORTNAME], int* attr, int numAttr){
  int found = 0;
  int i,j;

  struct Linfo* li = (struct Linfo*)malloc(sizeof(struct Linfo));
  strncpy(li->assoc, hwlocAssocStr, MAXSHORTNAME);
  snprintf(li->Lval,5,"%d",Lval);
  snprintf(li->Pval,5,"%d",Pval);
  li->nummetrics = 0;
  li->numchildren = 0;
  li->parent = NULL;

  // tree is really the current branch
  for (i=0; i<treesize; i++) {
    if ( !strncmp(tree[i]->assoc, hwlocAssocStr, MAXSHORTNAME) ) {
      tree[i] = li;
      treesize = i + 1;
      found = 1;
      break;
    }
  } 
  if (!found) {
    tree[treesize++] = li;
  }
  if (treesize > (MAXHWLOCLEVELS - 1)) {
    printf ("treesize exceeds limits\n");
    exit(0);
  }

  //NOTE: when use the LVAL for the naming convention, it is easier to read but then there
  //are some missing components -- for example
  //NUMANode:
  //  Machine0.Socket0.NUMANode0. 0.0.0.
  //	Machine0.Socket0.NUMANode1. 0.0.1.
  //	Machine0.Socket1.NUMANode2. 0.1.2.
  //	Machine0.Socket1.NUMANode3. 0.1.3.
  // there is NO 0.1.0 NOR 0.1.1

  //there is only 1 parent
  struct Linfo *parent = (treesize == 1 ? NULL: tree[treesize-2]);
  if (parent != NULL){
    li->parent = parent;
    li->parent->children[li->parent->numchildren++] = li;
  }

  //update the level interface as well 
  found = -1;
  for (i = 0; i < numlevels; i++){
    if (!strcmp(li->assoc,hwloc[i].assoc)){
      found = i;
      break;
    }
  }
  if (found == -1){
    strncpy(hwloc[numlevels].assoc,strdup(li->assoc),MAXSHORTNAME);
    hwloc[numlevels].numinstances = 0;
    found = numlevels;
    numlevels++; //this should be the same as the tree size
  }

  //add the attrs, if any as metrics
  for (i = 0; i < numAttr; i++){
    struct MetricInfo* mi = (struct MetricInfo*)malloc(sizeof(struct MetricInfo));
    snprintf(mi->ldmsname,MAXSHORTNAME,"%s","NONE");
    snprintf(mi->MIBmetricname,MAXSHORTNAME,"%s%s",HWLOCSTATICMETRICPREFIX,keys[i]); //note this is *not* an LDMS metric
    for (j = 0; j < MAXHOSTS; j++){
      mi->values[j] = attr[i];
    }
    mi->ldmsparent = NULL;

    //update the hw structs
    li->metrics[li->nummetrics] = mi;
    mi->MIBmetricUID = li->nummetrics++;
    mi->instance = li;

    //    printf("adding metric\n");
    //    printMetric(mi,1);

    //NOTE: do NOT update the ldms structs
  }
  
  //add the component
  hwloc[found].instances[hwloc[found].numinstances++] = li;

  for (i = 0; i < numknownassoc; i++){
    if (!strcmp(knownassoc[i], hwlocAssocStr)){
      return;
    }
  }

  //keep the assoc -- need to have non-conflicting assoc types
  snprintf(knownassoc[numknownassoc++],MAXSHORTNAME,"%s",hwlocAssocStr);
  for (i = 0; i < numknownassoc; i++){
    for (j = 0; j < i; j++){
      if (!strncmp(knownassoc[i],knownassoc[j],strlen(knownassoc[i])) ||
	  !strncmp(knownassoc[i],knownassoc[j],strlen(knownassoc[j]))){
	printf("Error: overlapping assoc types <%s> <%s>. Not structurally prepared to handle this.\n",
	       knownassoc[i], knownassoc[j]);
	exit (-1);
      }
    }
  }

}


int parseData(char* machineFile, char *hwlocFile, char LDMSData[MAXHWLOCLEVELS][MAXBUFSIZE], int numLDMSData){
  int i;
  int rc;

  rc = parseHwlocData(hwlocFile);
  if (rc != 0){
    printf("Error parsing hwloc data\n");
    cleanup();
    return rc;
  }


  //FIXME: give these a more permanent home...
  hostnameToHostOID = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);
  hostOIDToHostIndex = g_hash_table_new_full(g_str_hash, g_str_equal, NULL, NULL);

  rc = parseMachineData(machineFile);
  if (rc != 0){
    printf("Error parsing machine data\n");
    cleanup();
    return rc;
  }

  //   printHostnameToHostOIDHash();
  //   printHostOIDToHostIndexHash();

   
   
  //FIXME: is there some reason we cant have repeats???
  if (numLDMSData > 0  && (LDMSData != NULL)){
    for (i = 0; i < numLDMSData; i++){
      rc =  parseLDMSData(LDMSData[i]);
      if (rc < 0){
	printf("Error parsing ldms data\n");
	cleanup();
	return rc;
      }
    }
  }

  return rc;
  
}

int parseMachineData(char *file){
  //format will be hostname[space]Lval
  FILE *fd;
  char *s;
  char hostname[MAXLONGNAME];
  char Lval[5];
  char lbuf[MAXBUFSIZE];
  numhosts = 0;


  fd = fopen(file, "r");
  if (!fd) {
    printf("Could not open the file hwloc.out...exiting\n");
    return ENOENT;
  }
  fseek(fd, 0, SEEK_SET);
  do {
    s = fgets(lbuf, sizeof(lbuf), fd);
    if (!s)
      break;
    //      printf("fgets: <%s>\n", lbuf);
    if (lbuf[0] == '#'){
      continue;
    }

    int rc = sscanf(lbuf,"%s %s",hostname, Lval);
    if (rc == 0){
      //blankline
      continue;
    }

    if (rc != 2){
      printf("Error: bad host format <%s>\n", lbuf);
      cleanup();
      return -1;
    }

    if (numhosts > (MAXHOSTS-1)){
      printf("Error: too many hosts\n");
      cleanup();
      return -1;
    }

    //makes the hosts but does not assoc with the existing Linfo
    snprintf(hosts[numhosts].hostname, MAXLONGNAME, "%s", hostname);
    snprintf(hosts[numhosts].Lval,5,"%s", Lval);
    hosts[numhosts].index =  numhosts; 
    g_hash_table_replace(hostnameToHostOID,
			 (gpointer)hosts[numhosts].hostname,
			 (gpointer)hosts[numhosts].Lval);
    g_hash_table_replace(hostOIDToHostIndex,
			 (gpointer)hosts[numhosts].Lval,
			 (gpointer)&(hosts[numhosts].index));
    numhosts++;
  } while (s);
  fclose (fd);

  return 0;
}


int parseHwlocData(char* file){
   FILE *fd;
   char *s;
   char lbuf[MAXLONGNAME];
   char hwlocAssocStr[MAXSHORTNAME];
   char keys[MAXATTR][MAXSHORTNAME];
   int attrib[MAXATTR];
   int numAttrib;
   int Lval, Pval;

   if (tree[0] != NULL){
     printf("Error: cannot set another hwlocfile\n");
     return -1;
   }

   fd = fopen(file, "r");
   if (!fd) {
     printf("Could not open the file hwloc.out...exiting\n");
     return ENOENT;
   }
   fseek(fd, 0, SEEK_SET);
   do {
     s = fgets(lbuf, sizeof(lbuf), fd);
     if (!s)
       break;
     //      printf("fgets: <%s>\n", lbuf);
     if (parse_line(lbuf, hwlocAssocStr, &Lval, &Pval, keys, attrib, &numAttrib) == 0){
       //ignore the attributes for now
       addComponent(hwlocAssocStr, Lval, Pval, keys, attrib, numAttrib);
     }
   } while (s);
   fclose (fd);

   //FIXME: let the formats be dynamically set here or elsewhere
     

   return 0;
}

