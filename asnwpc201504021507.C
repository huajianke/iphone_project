//*****************************************************************************
// IBM Confidential
// OCO Source Materials
// 5655-DRP
// Copyright IBM Corp. 2013.
//   
// The source code for this program is not published or otherwise divested of 
// its trade secrets, irrespective of what has been deposited with the U.S. 
// Copyright Office.
//  DZH: Change IFI_FILTER default value to false for WPC
//  DZH: Comment out LOG_COMMIT_INTERVAL parm which is not contained in current code release
//*****************************************************************************
//test time:2015.04.01 15:55
#pragma comment(copyright, "Licensed Materials - Property of IBM. 5655-DRP Copyright IBM Corp. 2013 All Rights Reserved. US Government Users Restricted Rights - Use, duplication or disclosure restricted by GSA ADP Schedule Contract with IBM Corp.")

#ifdef OS_ZOS
  #pragma csect(CODE, "ASNWPC")
  #pragma runopts(POSIX(ON))
#endif //OS_ZOS

#include "asn.h"           // program version
#include "asntrace.h"      // trace definitions required in asnccp.h
#include "asnmsgl.h"       // msglogger functions
#include "asnmsgt.h"       // deprecated msgToLog functions
#include "asnccp.h"        // parameter definitions
#include "asnthred.h"      // thread functions
#include "asncryptinit.h"  // cryptInit
#include "asnbind.h"       // bindCommonLibFiles
#include "asnsqlcf.h"      // genLogfileName, getTabId
#include "asntxs.h"        // transmgr
#include "asnreg.h"        // registration
#include "asndecd.h"       // decodebase
#include "asnthred.h"      // thread

#include "asnwpctpcbmgr.h" // Transaction pattern control block manager.

///////////////////////////////////////////////////
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
///////////////////////////////////////////////////
// STL
//#include <list>

// Override some parms
#define RESTART_FILE             PRUNEMSG        //->13
#define TABLE_PREDICATE          PART_HIST_LIMIT //->39

#define KEEPCAPTURE              0  // If the main thread should keep working.
#define NONEEDTOCAPTUREMORE      1  // If the main thread should exit.

#define AsnRcWarnNoCDC           1

#define ARGUMENT_LINE_MAX        64                  // Maximum argument count
#define ARGUMENT_LINE_LENGTH_MAX 4096                // Maximum argument length

/*******************************************************************************
 * Internal functions
 ******************************************************************************/
int loadArgumentFile();

void freeGlobalArgument();

Uint16 processWPCArguments
(
  int             &argc, 
  char           **argv
);
                           
int initializeGlobals
(
  int              argc,
  char           **argv,
  OrdList          &mainThredList,
  recoveryRes*     &thredListRes,
  dbConn*          &mainConn);
                      
int createTransMgrAndStartLogrd
(
  asnDbRIB         &theRib, 
  transmgr*        &theTransMgr,
  logrd*           &logTxReader,
  logReaderClient* &dbTableMgr,
  asnLSN           &startingLSN
);

int verifyLogArchiving();                                

void initDefaultCCPTparms
(
  parmStruct ptr[CAP_PARAMETER_COUNT]
);

extern "C" void SIGINT_handler 
(
  int signum
);

int addInterestedTables(dbConn* conn, 
                        logReaderClient* logrdr, 
                        char* predicate);
Uint16 dumpTPCB
(
  Uint32 timepoint
);

/*******************************************************************************
 * Global variables
 ******************************************************************************/
char helpDescription[] =
" Specify WPC arguments in dd:WPCARG statement.\n"
" Arguments:\n"
"   DB=location            : Location of the database to monitor log from.\n"
"   AUTOSTOP=Y/N           : If WPC should automatically stop.\n"
"   DUMP_INT=n             : Interval in seconds for dumping workload profile.\n"
"   DUMP_SIZE=n            : Size limitation (MB) of dump file.\n"
"   DUMP_COUNT=n           : Count limitation of dump snapshots in dump file.\n"
"   DUMP_START=timestamp   : Time stamp as the start point to read log,\n"
"                            the format is yyyy-MM-dd-HH:mm:SS.\n"
"   WHERE=predicate        : The predicate to define the scope of monitor.\n"
"                            The predicate is appended to the query accessing\n"
"                            SYSIBM.SYSTABLES.\n"; 

sig_atomic_t  timeToQuit = 0;                 // If the main thread should quit.
int           globalArgc;                     // Global argument count
char         *globalArgv[ARGUMENT_LINE_MAX];  // Global argument array

//------------------------------------------------------------------------------
//
// Function Name: loadArgumentFile
//
// Descriptive-name: load argument file
//
// Function: Load arguments from file. For z/OS platform, the file is specified 
//           in JCL by dd:WPCARG. The other platforms are temporarily not 
//           supported.
// Syntax: N/A.
//
// Return: AsnRcOk          The file is loaded successfully.
//         AsnRcWPCParmFile Errors occured when loading the file. 
//------------------------------------------------------------------------------

#define ARGUMENT_LINE_MAX 64                         // Maximum argument count
#define ARGUMENT_LINE_LENGTH_MAX 4096                // Maximum argument length

int loadArgumentFile()
{
  char filename[256];
  char linebuffer[ARGUMENT_LINE_LENGTH_MAX];

#ifdef OS_ZOS        
  // Open file specified by dd:WPCARG
  sprintf(filename, "dd:WPCARG");
#else
  printf("ERROR Support z/OS platform only.\n");
  return AsnRcWPCParmFile;
#endif //OS_ZOS

  FILE *fp;
  fp = fopen(filename, "r");
  if ( fp == NULL )
  {
    printf("ERROR Can not open WPC argument file %s.\n", filename);
    return AsnRcWPCParmFile;
  }
  
  // Initialize global argument variables
  globalArgc = 1;       // Slot 0 is reserved for the program name.
  globalArgv[0] = NULL; // Slot 0 is not used.

  while( fgets(linebuffer, ARGUMENT_LINE_LENGTH_MAX-1, fp) != NULL ) 
  {
    int valueLen = strlen(linebuffer);

    // Remove all blank characters in tail.
    while ( valueLen >= 1 &&
            (linebuffer[valueLen-1] == '\n' || 
             linebuffer[valueLen-1] == '\t' ||
             linebuffer[valueLen-1] == ' ' ) )
    {
      linebuffer[valueLen-1] = '\0';
      valueLen--;
    }

    if ( valueLen <= 1 )
    {
      continue;
    }

    printf("INFO Load argument : %s\n", linebuffer);

    //--------------------------------------------------------------------------
    // [MEMORY] This space will be freed by freeGlobalArgument() which is called
    //          by main() after using all the arguments.
    //--------------------------------------------------------------------------
    globalArgv[globalArgc] = (char *)malloc(valueLen);
    strcpy(globalArgv[globalArgc], linebuffer);
    globalArgc++;
  } 

  fclose(fp);
  fp = NULL;

  return AsnRcOk;
}

//------------------------------------------------------------------------------
//
// Function Name: freeGlobalArgument
//
// Descriptive-name: free the space allocated for global arguments
//
// Function: Free the space allocated for global arguments.
//
// Syntax: N/A.   
//
//------------------------------------------------------------------------------
void freeGlobalArgument()
{
  for ( int i = 1 ; i < globalArgc ; ++i )
  {
    if ( globalArgv[i] != NULL )
    {
      free(globalArgv[i]);
      globalArgv[i] = NULL;
    } 
  }
}

//------------------------------------------------------------------------------
//
// Function Name: main
//
// Descriptive-name: main entry
//
// Function: The main entry of Workload Profile Capture (WPC). argc and argv are
//           ignored, dd:WPCARG is used to contain long and complex arguments.
//
//------------------------------------------------------------------------------
//--------------------------------------------------------------------------------------------------------
//								my code starts here
//--------------------------------------------------------------------------------------------------------
static MemoryBlock  decodeMem;
static TransPatternCBMgr &TPCBMgr = TransPatternCBMgr::getInstance();
static transmgr*        theTransMgr;                        // Transaction manager
static logrd*           logTxReader;                        // Log reader 
static logReadStats logStats;
static trans*       pTrans;
extern "C"  void  *threadEntry_getTrans(void *)
{
	getTrans( logTxReader,    // The log reader to use
              10000,          // Read no more than 10000 log records
              theTransMgr,
              &decodeMem,
              logStats,
              &pTrans);       // out: transaction if a commit was read
	return NULL;
}

extern "C"  void  *threadEntry_TPCB()
{
	return NULL;
}
//--------------------------------------------------------------------------------------------------------
//								my code ends here
//--------------------------------------------------------------------------------------------------------



int main(int argc, char *argv[])
{
  const char   funcName[]    = "asnccpt::main";

  int          rc            = AsnRcOk;
  dbConn*      mainConn      = NULL;
  OrdList      mainThredList;
  recoveryRes* thredListRes  = NULL;
  asnLSN       startingLSN;
  //MemoryBlock  decodeMem;//removed by zxt

  //TransPatternCBMgr &TPCBMgr = TransPatternCBMgr::getInstance();//removed by zxt

  printf("INFO WPC main entry starts.\n");

  //----------------------------------------------------------------------------
  // Load argument file to get all arguments saved in global argc and argv.
  //----------------------------------------------------------------------------
  rc = loadArgumentFile();

  if (rc)
  {
    printf("Wrong loading argument file.\n");
    trcbackMsg(funcName, "loadArgumentFile", rc, NULL);
    goto exit;
  }

  //----------------------------------------------------------------------------
  // Initialize program and parse commandline arguments.      
  //----------------------------------------------------------------------------
  rc = initializeGlobals(globalArgc,
                         globalArgv,
                         mainThredList, 
                         thredListRes,
                         mainConn);
                         
  if (rc)
  {
    printf("Wrong initializing global environment.\n");
    trcbackMsg(funcName, "initializeGlobals", rc, NULL);
    goto exit;
  }

  printf("INFO complete initialization of global parms.\n");

  // Free global argument heap 
  freeGlobalArgument(); 
 
  //----------------------------------------------------------------------------
  // Verify log archiving.
  //----------------------------------------------------------------------------
  rc = verifyLogArchiving();
  
  if (rc)
  {
    trcbackMsg(funcName, "verifyLogArchiving", rc, NULL);
    goto exit;
  } 
 
  printf("INFO Complete verifying log archiving.\n");
 
  //----------------------------------------------------------------------------
  // Create transaction manager and log reader thread.
  //----------------------------------------------------------------------------
  //transmgr*        theTransMgr;                        // Transaction manager//removed by zxt
  //logrd*           logTxReader;                        // Log reader //removed by zxt
  logReaderClient* dbTableMgr;                         // Log reader interface

  rc = createTransMgrAndStartLogrd(mainConn->dbRib, 
                                   theTransMgr,
                                   logTxReader,
                                   dbTableMgr,
                                   startingLSN);

  if (rc)
  {
    trcbackMsg(funcName, "createTransMgrAndStartLogrd", rc, NULL);
    goto exit;
  }

  // Set TPCB manager to reference the two object for decoding rows.
  TPCBMgr.dbTableMgr = dbTableMgr;  // Let TPCB manager has the handle
  TPCBMgr.decodeMem  = &decodeMem;  // Let TPCB manager has the handle

  printf("INFO Complete creating trans manager and log reader thread.\n");

  //---------------------------------------------------------------------------- 
  // Register tables
  //----------------------------------------------------------------------------
  {
    rc = addInterestedTables( mainConn, 
                              dbTableMgr, 
                              pAsnParm->getString(TABLE_PREDICATE));
    if (rc)
    {
      printf("ERROR Wrong in adding interested tables.RC=%d\n", rc);
      goto exit;
    }
  }
   
  printf("INFO Complete adding interested tables.\n");

  //--------------------------------------------------------------------------- 
  // Read the log and count transaction patterns.
  //---------------------------------------------------------------------------
  {
    //logReadStats logStats;//removed by zxt
    //trans*       pTrans;//removed by zxt
    Uint64       retrievedLogRecords = 0;

    TPCBMgr.TotalTimesDumped = 0;  // Explicity initialization
 
    while (!rc && !timeToQuit)
    {
      pTrans = NULL;   

      if (pAsnParm->getBool(DEBUG)) {
        printf("Start--- getting transaction.\n");
      }
 /* removed by zxt
      rc = getTrans( logTxReader,    // The log reader to use
                     10000,          // Read no more than 10000 log records
                     theTransMgr,
                     &decodeMem,
                     logStats,
                     &pTrans);       // out: transaction if a commit was read
       *///removed by zxt  
	  /////////////////////////////////////////////////////////////
	  pthread_t id;
	  int ret;
	  ret=pthread_create(&id,NULL,&threadEntry_getTrans,NULL);
	  if(0 == ret)
	  {
		  printf("Created thread successfully!\n");
	  }
	  else
		  printf("There are some errors occured when creating the thread!\n");
	  pthread_join(id,NULL);
	  /////////////////////////////////////////////////////////////
      if (pAsnParm->getBool(DEBUG)) {
        printf("End--- getting transaction.\n");
        if( pTrans != NULL )
        {
          pTrans->print();
        }
      }

      if (pTrans)
      {
        //----------------------------------------------------------------------
        // Add current transaction to TPCB manager.
        //----------------------------------------------------------------------
        TPCBMgr.addTrans(pTrans);

        //----------------------------------------------------------------------
        // Check if one dump point arrives.
        //----------------------------------------------------------------------
        Uint64 LatestLogTime    = TPCBMgr.getLatestLogTime();

        if ( LatestLogTime < TPCBMgr.DumpStartTimestamp * 1000LLU ) {
          // Should never occur.
          printf("ERROR latest log time is smaller than start point.\n");
          printf("INFO Latest log time: %lu\n", LatestLogTime);
          printf("INFO Dump start time: %d\n", TPCBMgr.DumpStartTimestamp);
        }

        Uint32 ClosestDumpPoint = 
                 (LatestLogTime - 
                  TPCBMgr.DumpStartTimestamp * 1000LLU) /
                 (TPCBMgr.DumpIntervalInSeconds * 1000LLU);

        if (pAsnParm->getBool(DEBUG)) {
          printf("INFO closest dump point is %u\n", ClosestDumpPoint);
        }

        if ( ClosestDumpPoint > TPCBMgr.TotalTimesDumped )
        {
          printf( "INFO Retrieved %d log records.\n", logStats.numlogRecsRead);
          printf( "INFO Start dump %d workload profile snapshot.\n",
                  TPCBMgr.TotalTimesDumped+1 ); 
          printf( "INFO Latest log dump point estimation:%d\n",
                  ClosestDumpPoint);
          printf( "INFO Captured table count:%u.\n",
                  TPCBMgr.CapturedTableCount);
          printf( "INFO Captured row count:%u, unable to decode row count %u.\n",
                  TPCBMgr.TotalRowCount,
                  TPCBMgr.UndecodedRowCount );
          printf( "INFO Recognized transaction pattern count:%u.\n",
                  TPCBMgr.TPCBCount );
          printf( "INFO Skipped transaction count:%u.\n", 
                  TPCBMgr.TransactionNoValidRows);


          Uint32 DumpTime = TPCBMgr.DumpStartTimestamp + 
                            (TPCBMgr.TotalTimesDumped + 1) * 
                            TPCBMgr.DumpIntervalInSeconds;
 
          if( dumpTPCB(DumpTime) != KEEPCAPTURE )
          {
            timeToQuit = 1;
          }
          TPCBMgr.TotalTimesDumped = ClosestDumpPoint; 

          if ( TPCBMgr.TotalTimesDumped >= TPCBMgr.DumpCount ) 
          {
            timeToQuit = 1;
          }
        }

        rc = theTransMgr->delTrans(pTrans);
        
        if (rc)
        {
          printf("INFO Returned %d with trans\n", rc);
          rc = AsnRcOk;
        }
        
      }
      else if (rc == AsnRcWarnEOL)
      {
        if (!pAsnParm->getBool(AUTOSTOP))
        {
          asnSleep(pAsnParm->getInt(SLEEP_INTERVAL));  
          rc = AsnRcOk;
        }
        else
        {
          pML->putAsnMsg( AsnMsg7020, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL);
        }
      }
      else if (rc == AsnRcWarnLogLimit)
      {
        // Still processing...
        rc = AsnRcOk;
      }
      
      if (decodeMem.size() > 0xA00000)
      {
        printf("INFO Decode memory is truncated.\n");
        decodeMem.truncate();
      }
    }
    
    printf("INFO WPC main threads goes to exit phase.\n");

    //--------------------------------------------------------------------------
    // If AUTOSTOP=y, the last dump point did not arrive yet. Dump the TPCB 
    // snapshot because there maybe some changes after the latest snapshot.
    //--------------------------------------------------------------------------
    if ( rc == AsnRcWarnEOL && 
         pAsnParm->getBool(AUTOSTOP) &&
         TPCBMgr.TotalTimesDumped < TPCBMgr.DumpCount )
    {
      Uint32 DumpTime = TPCBMgr.DumpStartTimestamp +
                        (TPCBMgr.TotalTimesDumped + 1) *
                        TPCBMgr.DumpIntervalInSeconds;
      dumpTPCB(DumpTime);
      TPCBMgr.TotalTimesDumped++;
    }

    //--------------------------------------------------------------------------
    // [MEMORY] Free all memory allocated for transaction pattern manager.
    //--------------------------------------------------------------------------
    TPCBMgr.freeAll();    

  }

 exit:

  printf("INFO Dump count:%d / %d\n", 
         TPCBMgr.TotalTimesDumped, 
         TPCBMgr.DumpCount );

  printf("INFO Dump total bytes:%d\n", 
         TPCBMgr.TotalBytesDumped );

  printf("INFO Total row count:%ld\n",
         TPCBMgr.TotalRowCount );

  printf("INFO Total not decoded row count:%ld\n",
         TPCBMgr.UndecodedRowCount );

  // Output tables that can not be decoded
  std::list<dbTable*> &dbTables = TPCBMgr.dbTables;
  for ( std::list<dbTable*>::iterator it = dbTables.begin(); 
        it!=dbTables.end(); 
        ++it )
  {
    dbTable* table = *it;
    if ( table->runtimeTableIndex >= 0 )
    {
      printf("INFO Captured table:%.*s.%.*s,",
             table->tabSchema.len, table->tabSchema.buffer,
             table->tabName.len, table->tabName.buffer);
      if ( table->runtimeTableCanNotDecode > 0 ) {
        printf(" %d rows can not be decoded.\n", table->runtimeTableCanNotDecode);
      }
      else {
        printf(" No rows are skipped.\n");
      }
    }
    else 
    {
      printf("INFO Not captured table:%.*s.%.*s\n",
             table->tabSchema.len, table->tabSchema.buffer,
             table->tabName.len, table->tabName.buffer);
    } 
  }
 
  pML->putAsnMsg( AsnMsg0573, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL);
  mainThread.threadExit(rc);
  
  return rc;
}

//------------------------------------------------------------------------------
// Parse WPC related arguments. And remove them from argument list. 
//
// DUMP_DIR=<directory>     : Set dump directory/ In z/OS, it is not required.
// DUMP_INT=<seconds>       : Set dump interval in seconds.
// DUMP_SIZE=<num>          : Set dump file size limit in MB. 512 means 512MB.
// DUMP_COUNT=<num>         : Set dump times limit.
// DUMP_START=yyyy-mm-dd-hh:MM:ss: Set first dump timestamp.
//------------------------------------------------------------------------------
#define COMMANDLINE_ARG_DUMP_DIR        "DUMP_DIR"
#define COMMANDLINE_ARG_DUMP_INT        "DUMP_INT"
#define COMMANDLINE_ARG_DUMP_FILESIZE   "DUMP_SIZE"
#define COMMANDLINE_ARG_DUMP_COUNT      "DUMP_COUNT"
#define COMMANDLINE_ARG_DUMP_START      "DUMP_START"
#define COMMANDLINE_ARG_DUMP_RCONLY     "DUMP_ROWCOUNTONLY"

//------------------------------------------------------------------------------
//
// Function Name: processWPCArguments
//
// Descriptive-name: process WPC specific arguments
//
// Function: Process WPC specific arguments. Global arguments are pased in.
// 
// Syntax: processWPCArguments ( argc,   // The argument count
//                               argv )  // The argument array
//
// Return AsnRcOk                 All arguments are valid.
//        AsnRcWPCArgDumpDir      Error, wrong dump directory setting. 
//                                (Not for DB2 z/OS)
//        AsnRcWPCArgDumpInt      Error, wrong dump interval setting.
//        AsnRcWPCArgDumpFileSize Error, wrong dump file limit setting.
//        AsnRcWPCArgDumpStart    Error, wrong dump start timestamp setting.
//        AsnRcWPCArgDumpLimits   Error, wrong dump limitation setting.
//
//------------------------------------------------------------------------------ 
Uint16 processWPCArguments(int &argc, char ** argv)
{
  int rc = AsnRcOk;
 
  //---------------------------------------------------------------------------
  // Legality of parameters.
  //   1) DUMP_INT, DUMP_START must be set.
  //   2) Either DUMP_COUNT or DUMP_FILESIZE must be set.
  //   3) For WPC z/OS version, DUMP_DIR is not processed, it is ignored.
  //---------------------------------------------------------------------------
 
  bool setValueDumpDir      = false;
  bool setValueDumpInt      = false;
  bool setValueDumpFilesize = false;
  bool setValueDumpCount    = false;
  bool setValueDumpStart    = false;

  for ( int argIndex = 1 ; argIndex < argc ; ++argIndex )
  {
    // Extract argument name part.
    char tmpArgName[64];
    int cindex = 0;
    for ( ; 
          (argv[argIndex][cindex] != '\0') && 
          (argv[argIndex][cindex] != '=' ) &&
          (cindex < sizeof(tmpArgName)-1) ;
          ++cindex )
    {
      tmpArgName[cindex] = toupper(argv[argIndex][cindex]);
    }
    tmpArgName[cindex]='\0';
    
    // Ensure that connector '=' exists, the sub-string which starts from '=' is
    // the value part.
    if (  argv[argIndex][cindex] != '=' )
    {
      continue;
    }    
    
    // Set value as parameter values which are saved in TPCBMgr.
    char *pValue = &(argv[argIndex][cindex+1]);

    if ( strcmp( tmpArgName, COMMANDLINE_ARG_DUMP_DIR ) == 0 )
    {
#ifdef OS_ZOS
      fprintf(stdout, 
              "INFO Dump directory parameter is ignored "
              "in z/OS version WPC.\n");
#else
      rc = TransPatternCBMgr::getInstance().setDumpDirectory(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump directory setting. %s\n", pValue);
        return rc;
      }
      setValueDumpDir = true;
      fprintf(stdout, "INFO Set dump directory to %s\n", pValue);
#endif //OS_ZOS
    }
    else if ( strcmp( tmpArgName, COMMANDLINE_ARG_DUMP_INT ) == 0 )
    {
      rc = TransPatternCBMgr::getInstance().setDumpIntervalInSeconds(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump interval in seconds setting."
                        " %s\n", pValue);
        return rc;
      }
      setValueDumpInt = true;
      fprintf(stdout, "INFO Set dump interval in seconds to %s\n", pValue);
    }
    else if ( strcmp( tmpArgName, COMMANDLINE_ARG_DUMP_FILESIZE ) == 0 )
    {
      rc = TransPatternCBMgr::getInstance().setDumpFileSizeLimit(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump file size limit setting."
                        " %s\n", pValue);
        return rc;
      }
      setValueDumpFilesize = true;
      fprintf(stdout, "INFO Set dump file size limit is %s MB\n", pValue);
    }
    else if ( strcmp( tmpArgName, COMMANDLINE_ARG_DUMP_START ) == 0 )
    {
      rc = TransPatternCBMgr::getInstance().setDumpStartpoint(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump start point setting."
                        " %s\n", pValue);
        return rc;
      }
      setValueDumpStart = true;
      fprintf(stdout, "INFO Set dump start point is %s\n", pValue);
    }
    else if ( strcmp (tmpArgName, COMMANDLINE_ARG_DUMP_COUNT ) == 0 )
    {
      rc = TransPatternCBMgr::getInstance().setDumpCount(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump count setting."
                        "%s\n", pValue);
        return rc;
      }
      setValueDumpCount = true;
      fprintf(stdout, "INFO Set dump count is %s times.\n", pValue);
    }
    else if ( strcmp (tmpArgName, COMMANDLINE_ARG_DUMP_RCONLY ) == 0 )
    {
      rc = TransPatternCBMgr::getInstance().setDumpRowCountOnlyMode(pValue);
      if ( rc )
      {
        fprintf(stdout, "ERROR Wrong dump mode setting."
                        "%s\n", pValue);
        return rc;
      }
      fprintf(stdout, "INFO Set decode mode is %s.\n", pValue);
    }
    else
    {
      // The parameter should be standard Capture ones, so ignore it. 
      fprintf(stdout, "INFO Skip parameter line:%s.\n", pValue);
      continue;
    }
    
    // Remove the argv[argIndex] if it is for WPC arguments.
    for ( int i = argIndex ; i < argc-1 ; ++i ) 
    {
      argv[i] = argv[i+1];
    }
    argc--;          
    argIndex--;     // Make next loop handle the same position.
    
  } // End for all arguments

#ifndef OS_ZOS  
  // Must set dump directory and dump interval.
  if ( !setValueDumpDir )
  {
    fprintf(stdout, "INFO Miss dump directory argument.\n");
    return AsnRcWPCArgDumpDir;
  }
#endif

  if ( !setValueDumpInt )
  {
    fprintf(stdout, "INFO Miss dump interval in seconds argument.\n");
    return AsnRcWPCArgDumpInt;
  }
  if ( !setValueDumpStart )
  {
    fprintf(stdout, "INFO Miss dump start timestamp argument.\n");
    return AsnRcWPCArgDumpStart;
  }
  if ( !setValueDumpCount && !setValueDumpCount )
  {
    fprintf(stdout, "INFO Miss dump count and dump file limit arguments.\n");
    return AsnRcWPCArgDumpLimits;
  }
  return AsnRcOk;
}

//------------------------------------------------------------------------------
//
// Function Name: initializeGlobals
//
// Descriptive-name: initialize global execution environment
//
// Function: Initialize global environment and parse command line. CAPTURE
//           corresponding arguments are processed in this function.
//
// Syntax: initializeGlobals ( argc,           // Argument count
//                             argv,           // Argument array
//                             mainThredList,  // Thread list
//                             thredListRes,   // Register thread for recovery
//                             mainConn )      // The connection to database

// Return AsnRcOk       All initialization work is done without errors.
//------------------------------------------------------------------------------
int initializeGlobals
(
  int          argc,
  char**       argv,
  OrdList      &mainThredList,
  recoveryRes* &thredListRes,
  dbConn*      &mainConn
)
{
  int rc = AsnRcOk;
  const char funcName[] = "initializeGlobals";
  
  const char connType = 
#ifdef OS_ZOS
    Db2Zseries;
#elif ORACAP
    DbOracle;
#else
    Db2LUW;
#endif

  // WPC supports only DB2 LUW and DB2 z/OS now.
  if ( connType != Db2Zseries && connType != Db2LUW )
  {
    goto exit;
  }  
  //----------------------------------------------------------------------------
  // Create message logger. pML is an external varialble to hold the message
  // logger object.
  // TODO: Check more details of message logger.
  //----------------------------------------------------------------------------
  pML = createMsgLogger( appWPC, ML_NOQUEUE );  
  if (pML == NULL)  
  {
     // Disaster!! cannot use msgLogger 
     printf("ASN8034D  \"Capture Capacity Planning Tool\" : \"*\" : \"main\" : "
            "Cannot allocate memory for \"msgLogger\".\n");
    mainThread.threadExit(-1);
  }  
  // newMessages is one external variable with pre-defined messages.
  pML->addMsgCatExtensions(newMessages);

  
  //----------------------------------------------------------------------------
  // Initialize this thread work environment. On a non-zero return code,
  // must exit immediately.
  // mainThread is external variable as the main asn thread.
  //----------------------------------------------------------------------------
  threadPrologue(rc, &mainThread);
  if (rc)
  {
    trcbackMsg(funcName, "threadPrologue", rc, NULL);
    goto exit;
  }
  
  //----------------------------------------------------------------------------
  // Override the piece of shit signal handler code with something that handles
  // SIGINT only. What is a shit? :-)
  //----------------------------------------------------------------------------
  
  struct sigaction sa;
  sigemptyset (&sa.sa_mask);
  sa.sa_flags = 0; 
  sa.sa_handler = SIGINT_handler;
  sigaction (SIGINT, &sa, 0);

  //----------------------------------------------------------------------------
  // Initialize the TRACE facility
  //----------------------------------------------------------------------------
  trcInit();

  //----------------------------------------------------------------------------
  // Initialize program arguments
  //----------------------------------------------------------------------------
  parmStruct WPCparms[ CAP_PARAMETER_COUNT ];

  printf ("INFO: start initialization of WPC parms.\n");
  initDefaultCCPTparms(WPCparms); 
  printf ("INFO: complete initialization of WPC parms.\n");

  capParmClass* capParms;
                capParms = new capParmClass(WPCparms, CAP_PARAMETER_COUNT, &rc);
  
  if (!capParms)
  {
     // Disaster!! cannot use msgLogger 
     printf("ASN8034D  \"Capture Capacity Planning Tool\" : \"*\" : \"main\" : "
            "Cannot allocate memory for \"capParms\".\n");
    mainThread.threadExit(-1);
  }
  else if (rc)
  {
    trcbackMsg(funcName, "setParms", rc, NULL);
    goto exit;
  }

  pAsnParm            = capParms;
  pAsnParm->helpDesc  = helpDescription;
  pAsnParm->modifyCmd = NULL;

  
  //------------------------------------------------------------------------
  // Set the Environment DPropr Release Information Block (RIB). amongst 
  // other things, this is used to determine which logreader to invoke.
  //------------------------------------------------------------------------
  pAsnEnv->setEnvDprRIB( "wpc",            // program name
                         AsnVersion,
                         AsnRelease,
                         AsnModification);

  //------------------------------------------------------------------------
  // Intialize thread list.
  // Register the thread list for recovery. If the initial thread dies,
  // recovery will call stopAllThreads. (This list is serialized)
  //------------------------------------------------------------------------
  mainThredList.init("main_threadlist ", ASNTRUE); 
  thredListRes = addRcvyRes(&erStopThreads, &mainThredList);

  //------------------------------------------------------------------------
  // Parse the command-line arguments
  //------------------------------------------------------------------------
  
  // Parse the WPC related special arguments.
  rc = processWPCArguments(argc, argv);
  if (rc)
  {
    trcbackMsg(funcName, "processWPCArguments", rc, NULL);
    goto exit;
  }
  
  // Parse the other CAPTURE derived argumnts.
  rc = pAsnParm->processCommandLine(argc, argv);
  if (rc)
  {
    trcbackMsg(funcName, "processCommandLine", rc, NULL);
    goto exit;
  } 
  
  // Set our process-level connection variables
  rc = mainThread.setConnVars(pAsnParm->getString(ASNDBNAME), // SUBSYS    (Z)
                              "WPCWC101 ",                    // PLAN name (Z)
                              ASNFALSE);                      // single ctx mode
  
  //-------------------------------------------------------------------------
  // Setup input arguments for database connect. The target database type is
  // decided by connType ( DB2 z/OS or DB2 LUW ).
  //-------------------------------------------------------------------------

  fprintf(stdout, "Start initialiazing connection.\n");
  mainConn = mainThread.initConn(connType, 
                                 pAsnParm->getString(ASNDBNAME),
                                 (int (*)()) bindCommonLibFiles);

  fprintf(stdout, "Complete initialiazing connection.\n");
                                 
  if (!mainConn)
  {
    char msgBuf[20];
    sprintf(msgBuf, OSS_PRIdSZT, sizeof(dbConn));
    msgToLog(AsnMsg0543, funcName, ALL, NULL, NULL, 2, msgBuf, "dbConn");
    goto exit;
  }

  //---------------------------------------------------------------------------
  // initialize the crypt context for the password encryption 
  //---------------------------------------------------------------------------
  rc = initCryptContext();
  if (rc)
  {
    trcbackMsg(funcName, "initCryptContext", rc, NULL);
    goto exit;
  } 
  
  //-------------------------------------------------------------------------
  // Attempt to connect to our server
  //-------------------------------------------------------------------------
  rc = mainThread.connect(mainConn, pAsnEnv);
  if (rc)
  {
    trcbackMsg(funcName, "connect", rc, NULL);
    goto exit;
  } 

  printf("Complete connection.\n"); 
   
#ifndef OS_ZOS
  //
  // For pureScale FP2, we ONLY support reading the log from a purescale DB
  //
  if (!mainConn->dbRib.isDB2LUWSupportingPureScale())
  {
    //--------------------------------------------------------------------------
    // ASN0647E $1 : $2 :  The version $3 of capture server $4 is not supported
    //   by this version of the Capture or Q Capture program.
    //--------------------------------------------------------------------------
    char dbVersion[15];
    ossSnprintf(dbVersion, sizeof(dbVersion), "%d.%d.%d", 
                mainConn->dbRib.dbrel.version,
                mainConn->dbRib.dbrel.release,
                mainConn->dbRib.dbrel.modification);
    char ccptVersion[15];
    ossSnprintf(ccptVersion, sizeof(ccptVersion), "%d.%d.%d", 
                AsnVersion,
                AsnRelease,
                AsnModification);
    char msgText[250];
    ossSnprintf(msgText, sizeof(msgText),
                "The version %s of the database server '%s' is not supported "
                "by this version of the capacity planning tool (%s).",
                dbVersion, pAsnParm->getString(ASNDBNAME), ccptVersion);
    pML->putAsnMsg( AsnMsg8999, MLD_STDOUT, funcName, NULL, msgText);
    rc = AsnRcFuncUnImpl;
    goto exit;    
  }
#endif //OS_ZOS 
     
  //-------------------------------------------------------------------------
  // Set the unique prefix that this MQCAP instance will use for generating
  // names of files that it will create (eg, trace files)
  //  WARNING: Must be called AFTER setEnvDprRIB
  //           Must be called AFTER processCommandLine
  //-------------------------------------------------------------------------
  rc = pAsnEnv->setEnvNamePrefix("WPC");
  if (rc)
  { 
    trcbackMsg(funcName, "asnEnv::setEnvNamePrefix", rc, NULL);
    rc = AsnRcTermDb;
    goto exit;
  } 

  //-------------------------------------------------------------------------
  // Make sure the instance path is set
  //  WARNING: Must be called AFTER mainDbCon.dbInit
  //-------------------------------------------------------------------------
  if (pAsnEnv->getEnvInstPath() == NULL)
  {
    trcbackMsg(funcName, "asnEnv::getEnvInstPath", rc, NULL);
    rc = AsnRcDbNoInstance;
    goto exit;
  } 

  //------------------------------------------------------------------------
  // Set msglogger qualifier (todo - see if this can be removed)
  //------------------------------------------------------------------------
  pML->setMsgQualifier("ASN");
  {
    char logFileName[PATH_MAX];
    genLogFileName(logFileName,
                   pAsnParm->getString(ASNPATH),
                   pAsnEnv->getEnvNamePrefix());
    // This activates output to the log file destination               
    pML->setMsgOutLog(pAsnParm->getString(ASNPATH),logFileName);
  }
        
  // If command line specified LOGREUSE=Y then clear the log file now
  if (pAsnParm->getBool(LOGREUSE))
  {  
     pML->clearLogFile();
  }
  
  // Generate a restart file name if the user didn't provide one explicitly
  if (!strcmp(pAsnParm->getString(RESTART_FILE), ""))
  {
    char restartFileName[128];
    ossSnprintf(restartFileName, sizeof(restartFileName),
                "%s%c.%s.CCPT.restartfile",
                pAsnParm->getString(ASNPATH),
                OSS_PATH_SEP,
                pAsnParm->getString(ASNDBNAME));
    
    pAsnParm->setParm(RESTART_FILE, restartFileName, ASN_DEFAULT);
  }
  
  printf( "Complete initializing globals.\n");
  
  pAsnParm->printParms();
  
 exit:
  return rc;
}  // end initializeGlobals

//------------------------------------------------------------------------------
// 
// Function Name: dumpTPCB
//
// Descriptive-name: dump TPCB data to data set/file.
//
// Function: Dump TPCB Data to file. This is called by main() when all TPCB data
//           should be dumped to file or data set.
//
// Syntax: dumpTPCB ( timepoint ) // The dump timepoint in seconds
//
// return NONEEDTOCAPTUREMORE   if something is wrong or file size is limited.
//        KEEPCAPTURE           if can dump again.
//
//------------------------------------------------------------------------------
Uint16 dumpTPCB(Uint32 timepoint)
{
  // Ascii code of "DUMPHEAD"
  static const char FILEHEAD[]=
    { 0x44, 0x55, 0x4D, 0x50, 0x48, 0x45, 0x41, 0x44 };

  // Ascii code of "TPCBDUMP"
  static const char DUMPHEAD[]=
    { 0x54, 0x50, 0x43, 0x42, 0x44, 0x55, 0x4D, 0x50 };

  TransPatternCBMgr *pTPCBMgr = &TransPatternCBMgr::getInstance();

  //----------------------------------------------------------------------------
  // If data to dump is too large to write to the file, stop dump.
  //----------------------------------------------------------------------------
  Uint32 toDumpSize = pTPCBMgr->getToDumpSize();
  if ( pTPCBMgr->TotalBytesDumped + toDumpSize + 16 >
       pTPCBMgr->DumpFileSizeLimit*1024*1024 )
  {
    printf("INFO Dump file size limit achieved.\n");
    return NONEEDTOCAPTUREMORE;
  }                   
  pTPCBMgr->TotalBytesDumped += toDumpSize + 16;  

  //----------------------------------------------------------------------------
  // Begin to dump data to file
  //----------------------------------------------------------------------------
  time_t currSystemTime = time(NULL);
  printf("INFO Dump data when (%s).\n", ctime(&currSystemTime));

  FILE *fp = NULL;
  char filename[16];

#ifdef OS_ZOS
  sprintf(filename, "dd:WPCDMP");

  // Try to read the file to check if the file exists
  fp = fopen(filename, "r");
  if ( fp == NULL )
  {
    printf("ERROR Can not open file %s\n", filename);
    return NONEEDTOCAPTUREMORE; // Quit
  }
  else
  {
    fclose(fp);
    fp = NULL;
  }
#else
  sprintf(filename, "%s", dumpDir);
#endif //OS_ZOS

  printf("INFO Dump to file %s\n", filename);

  //----------------------------------------------------------------------------
  // Read all TPCB binary memroy buffer, and write them out to the file.
  //----------------------------------------------------------------------------

#ifdef OS_ZOS
  // Open file
  fp = fopen( filename, "ab");
#else
  fp = fopen( filename, "ab+" );
#endif //OS_ZOS

  if ( fp == NULL )
  {
    printf( "ERROR Can not open dump file %s\n", filename);
    return NONEEDTOCAPTUREMORE;
  }

  TPCBBuffer *pBufPtr  = pTPCBMgr->__bufferPtr;
  TPCBBuffer *pBufHead = pBufPtr;

  // Write head of dump. This is a const string of 8 chars.
  if ( fwrite(DUMPHEAD, 1, sizeof(DUMPHEAD), fp) != (sizeof(DUMPHEAD)) )
  {
    fprintf( stdout,
             "ERROR DUMP THREAD ERR:"
             " Can not write dump head tag to file %s.\n",
             filename);
    return NONEEDTOCAPTUREMORE; // Fail to write. Something is wrong.
  }

  // Write dump timestamp. This is a 64-bit integer as micro seconds from 1970.
  Uint64 seconds = timepoint;
  if ( fwrite(&seconds, 1, sizeof(Uint64), fp) != sizeof(Uint64) )
  {
    fprintf( stdout,
             "ERROR Can not write dump timepoint to file %s.\n",
             filename);
    return NONEEDTOCAPTUREMORE; // Fail to write. Something is wrong.
  }

  int toWriteSize = 0;
  while ( pBufPtr != NULL )
  {
    // Write one TPCB buffer.
    toWriteSize = pBufPtr->sizeToDump();

    int ws = fwrite( (void *)pBufPtr, 1, toWriteSize, fp );
    if ( ws != toWriteSize )
    {
      fprintf( stdout,
               "Error DUMP THREAD ERR:"
               " Can not write buffered TPCBs to file %s\n",
               filename);
      return NONEEDTOCAPTUREMORE; // Fail to write. Something is wrong.
    }

    printf("INFO Write TPCB buffer, size=%d.\n", toWriteSize);

    pBufPtr = pBufPtr->next();
  }

  printf("INFO Close dump file %s\n", filename);
  fclose(fp);
  fp = NULL;


  return KEEPCAPTURE;
}

//------------------------------------------------------------------------------
//
// Function Name: createTransMgrAndStartLogrd
//
// Desciptive-name: create transaction manager and start log reader
//
// Function: Create transaxtion manager and start log reader thread.
//
// Syntax: createTransMgrAndStartLogrd (
//           theRib,
//           theTransMgr,
//           logTxReader,
//           dbTableMgr,
//           startingLSN )
//
// Return AsnRcOk      If there is no error.
//
//------------------------------------------------------------------------------
int createTransMgrAndStartLogrd
(
  asnDbRIB         &theRib, 
  transmgr*        &theTransMgr,
  logrd*           &logTxReader,
  logReaderClient* &dbTableMgr,
  asnLSN           &startingLSN
)
{
  int           rc = AsnRcOk; 
  const char    funcName[] = "createTransMgrAndStartLogrd";
  asnLSN        lastCommitLSN;
  char          startingLSNStr[100];
  // Timestamp of last commit record seen
  char          lastCmtTs[SQL_STAMP_DEF_STRLEN+1];  
  // Time (secs) of last commit record seen
  OSSTime       lastCommitTime = {0};  
  char          nodeNumbersStr[100];  
  
  ASNBOOL isColdStart = ASNFALSE;

  printf("INFO Transaction manager memory limit is %d MB.\n",
         pAsnParm->getInt( MEMORY_LIMIT ) );

  lastCommitTime.time = TransPatternCBMgr::getInstance().DumpStartTimestamp;
  lastCommitLSN = *(TransPatternCBMgr::getInstance().DumpStartLSN);
  //----------------------------------------------------------------------------
  // Create transmgr
  //----------------------------------------------------------------------------
  theTransMgr = new transmgr(rc,
                            &lastCommitLSN,
                             lastCommitTime,
                             pAsnParm->getInt( MEMORY_LIMIT ) * 1000000,
                             NULL, // Ignore signals
                             NULL, // Ignore signals
                             theRib);

  printf("INFO Complete creating transaction manager.\n");
                             
  dbTableMgr = new WPClogReaderClient();
                      
  if (rc)
  {
    trcbackMsg(funcName, "transmgr::transmgr", rc, NULL);
    goto exit;
  } // end cannot create the transmgr
  
  printf("INFO Complete creating log reader client.\n");

  rc = createLogReader(*dbTableMgr, &logTxReader);

  if (rc)
  {
    trcbackMsg(funcName, "createLogReader", rc, NULL);
    goto exit;
  } 

  printf("INFO Complete creating log reader.\n");
  
  theTransMgr->attach_logrd( logTxReader );
  
  logTxReader->getCurrentActiveLsn( &startingLSN );
  
  startingLSN.format(startingLSNStr, sizeof(startingLSNStr), 
                     "The latest log will begin at LSN '","'");
  
  printf("INFO %s\n", startingLSNStr);
                
  pML->putAsnMsg( AsnMsg8999, STDOUTMSG, funcName, NULL, startingLSNStr);  
  
  
  nodeNumbersStr[0] = '\0';

  // Set start LSN for logreader
  rc = logTxReader->setNextReadLsn( &lastCommitLSN );
  
  // Reset warnings 
  if ((rc  == AsnRcWarnLessNode) || (rc == AsnRcWarnMoreNode)) 
  {
    rc = AsnRcOk; 
  }  

 exit:
  return rc;
}  // end createTransMgrAndStartLogrd

//------------------------------------------------------------------------------
// 
// Function Name: verifyLogArchiving
//
// Descriptive-name: verify the log archiving option
//
// Function: Check that LOGRETAIN is ON in the database configuration. This is
//           required for only DB2 LUW. This is a noop on Oracle and DB2 z/OS.
//         
//           The checking is done by asnEnv::checkLogRetainSetting() which 
//           implements the check for different databases, thus in this function, 
//           MACRO for compilation is NOT needed.
// 
// Return AsnRcOk    The log archiving setting is correct. 
//
//------------------------------------------------------------------------------
int verifyLogArchiving()
{
  int rc = AsnRcOk;
  const char funcName[] = "verifyLogArchiving";
  
  //---------------------------------------------------------------------
  // Check that LOGRETAIN is ON in the database configuration only on UWL
  //---------------------------------------------------------------------
  rc = pAsnEnv->checkLogRetainSetting(); 
  if (rc)
  {
    trcbackMsg(funcName, "asnEnv::getLogRetainSetting", rc, NULL);
    //--------------------------------------------------------------------------
    // ASN0539E %1 : Database or subsystem named %1 needs to be configured with
    //          LOGRETAIN=ON or LOGRETAIN=CAPTURE.
    //--------------------------------------------------------------------------
    pML->putAsnMsg( AsnMsg0539, 
                    MLD_STDOUT, 
                    funcName, 
                    NULL, 
                    pAsnParm->getString(ASNDBNAME));
                    
    rc = AsnRcTermDb;
    goto exit;
  } // end LOGRETAIN is not ON

exit:
  return rc;
}  // end verifyLogArchiving

//------------------------------------------------------------------------------
// 
// Function Name: initDefaultCCPTparms
//
// Descriptive-name: Initialize some default parameters.
//
// Function: Initialize default parameters. These parameters are derived from
//           Q Replication CAPTURE.
//
//-----------------------------------------------------------------------------
void initDefaultCCPTparms(parmStruct ptr[CAP_PARAMETER_COUNT])
{
  //-- Initialize the common parameters (see asnparms.h)
  ptr[0]  = initParmBool(DEBUG,            "DEBUG",       
                                            0, ASNFALSE, ASN_QUERYABLE_IF_SET);
  ptr[1]  = initParmBool(AUTOSTOP,         "AUTOSTOP",    
                                            5, ASNFALSE, ASN_QUERYABLE_ALWAYS);
  ptr[2]  = initParmString(ASNPATH,        "CAPTURE_PATH",
                                            10, "", 0, ASN_QUERYABLE_ALWAYS);
  ptr[3]  = initParmString(ASNDBNAME,      "DB",          
                                            2,  "", 0, ASN_QUERYABLE_ALWAYS);
  ptr[4]  = initParmString(ASNSCHEMAQUAL,  "SCHEMA", 
                                            0, DefSchema, MAX_TAB_SCHEMA, ASN_QUERYABLE_ALWAYS);
  // PART_HIST_LIMIT (39->5)->used for TABLE_PREDICATE
#ifdef OS_ZOS
  ptr[5]  = initParmString(TABLE_PREDICATE,"WHERE", 0,
                                           "CREATOR LIKE '%' AND NAME LIKE '%'",
                                            5000, ASN_QUERYABLE_IF_SET);
#else
  ptr[5]  = initParmString(TABLE_PREDICATE,"WHERE", 0,
                                           "TABSCHEMA LIKE '%' AND TABNAME LIKE '%'",
                                            5000, ASN_QUERYABLE_IF_SET);
#endif //OS_ZOS
  // WARNTXSZ: 41->6
  ptr[6]  = initParmInt(WARNTXSZ,          "WARNTXSZ", 
                                            0, 0, DefMax, 0, ASN_QUERYABLE_ALWAYS);
  ptr[7]  = initParmBool(LOGREUSE,         "LOGREUSE",     
                                            4, ASNFALSE, ASN_QUERYABLE_ALWAYS);
  ptr[8]  = initParmBool(LOGSTDOUT,        "LOGSTDOUT", 
                                            0, ASNFALSE, ASN_QUERYABLE_ALWAYS);
  ptr[9]  = initParmInt(MEMORY_LIMIT,      "MEMORY_LIMIT", 2,
                        DefMin,
                        DefMax,
                        DefMemoryLimit,
                        ASN_QUERYABLE_ALWAYS);
  // ASNDBRANGE 20->10
  ptr[10] = initParmInt(ASNDBRANGE,        "ASNDBRANGE", 0, 
                        1, 
                        99, 
                        99, 
                        ASN_QUERYABLE_ALWAYS);
  ptr[11] = initParmInt(MONITOR_INTERVAL,  "MONITOR_INTERVAL", 9,
                        DefMin,
                        DefMax,
                        DefMonitorInterval,
                        ASN_QUERYABLE_ALWAYS );
  // LOGRDBUFSZ 36->12
  ptr[12] = initParmInt(LOGRDBUFSZ,        "LOGRDBUFSZ", 0,
                        MinLogrdBufSz,
                        MaxLogrdBufSz,
                        DefLogrdBufSz,
                        ASN_QUERYABLE_ALWAYS);
  // PRUNEMSG (13) used for RESTART_FILE
  ptr[13] = initParmString(RESTART_FILE,   "RESTART_FILE", 
                           0, "", 0, ASN_QUERYABLE_ALWAYS);
  // PWDFILE 23->14
  ptr[14] = initParmString(PWDFILE,        "PWDFILE",      
                           0, "", 0, ASN_QUERYABLE_IF_SET);
  ptr[15] = initParmInt(SLEEP_INTERVAL,    "SLEEP_INTERVAL", 2,
                        DefMin,
                        DefMax,
                        DefSleepInterval,
                        ASN_QUERYABLE_ALWAYS);
  ptr[16] = initParmString(STARTMODE,      "STARTMODE", 
                           2, "WARMSI",  0, ASN_QUERYABLE_ALWAYS);
  // LOGBUF 22->17
  ptr[17] = initParmInt(LOGBUF,            "LOGBUF", 0, 
                        0, 
                        DefMax, 
                        0, 
                        ASN_QUERYABLE_ALWAYS);    

  // Unused parameters -  
  ptr[18] = initParmInt(TRACE_LIMIT, "ASNPLACEHOLDER", 2,
                         DefMin,
                         DefMax,
                         DefTraceLimit,
                         ASN_NON_QUERYABLE);
  ptr[19] = initParmBool(DIAGLOG, "ASNPLACEHOLDER", 0, ASNTRUE, ASN_NON_QUERYABLE);
  // RETENTION_LIMIT 14->20
  // ASNDBRANGE 20->12
  ptr[20] = initParmInt(RETENTION_LIMIT,  "ASNPLACEHOLDER", 1,
                        DefMin,
                        DefMax,
                        DefRetentionLimit,
                        ASN_NON_QUERYABLE);
  // PRUNE_INTERVAL 12->21
  ptr[21] = initParmInt(PRUNE_INTERVAL,   "ASNPLACEHOLDER", 0,
                         DefMin,
                         DefMax,
                         DefPruneInterval,
                         ASN_NON_QUERYABLE);
  // AUTOPRUNE 0->22
  ptr[22] = initParmBool(AUTOPRUNE, "ASNPLACEHOLDER", 5, ASNTRUE, ASN_NON_QUERYABLE);
  // MONITOR_LIMIT 10->23
  ptr[23] = initParmInt(MONITOR_LIMIT, "ASNPLACEHOLDER", 9,
                        DefMin,
                        DefMax,
                        DefMonitorLimit,
                        ASN_NON_QUERYABLE);
  ptr[24] = initParmString(REMOTE_SRC_SERVER, "ASNPLACEHOLDER", 0, "", 18,   ASN_NON_QUERYABLE);
  ptr[25] = initParmBool(ADD_PARTITION,       "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[26] = initParmBool(C_ASNTRC,            "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[27] = initParmBool(C_TRCSTART,          "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[28] = initParmBool(CAF, "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[29] = initParmBool(MIGRATE, "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[30] = initParmInt(TEST_HOOK, "ASNPLACEHOLDER", 0, 0, 99, 0,
                        ASN_NON_QUERYABLE);
  ptr[31] = initParmString(TRANSID, "ASNPLACEHOLDER", 0, "", 29, ASN_NON_QUERYABLE);
  //  Change IFI_FILTER default value to false for WPC
  ptr[32] = initParmBool(IFI_FILTER, "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);  
  ptr[33] = initParmString(TRANSID_SHORT, "ASNPLACEHOLDER", 0, "", 29, ASN_NON_QUERYABLE);
  ptr[34] = initParmString(ARM, "ASNPLACEHOLDER", 0, "", 16, ASN_NON_QUERYABLE);
  ptr[35] = initParmInt(STALE, "ASNPLACEHOLDER", 0, 1, DefMax, 3600, ASN_NON_QUERYABLE);
  // LOGRDBUFSZ 36->12
  // TERM 17->36
  ptr[36] = initParmBool(TERM, "ASNPLACEHOLDER", 2, ASNTRUE, 1, ASN_NON_QUERYABLE);
  ptr[37] = initParmBool(HIPERSPACE, "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  ptr[38] = initParmBool(IGNCASDEL, "ASNPLACEHOLDER", 0, ASNFALSE, ASN_NON_QUERYABLE);
  // LAG_LIMIT 6->39
  // PART_HIST_LIMIT (39->5)->used for TABLE_PREDICATE
  ptr[39] = initParmInt(LAG_LIMIT, "ASNPLACEHOLDER", 2,
                        DefMin,
                        DefMax,
                        DefLagLimit,
                        ASN_NON_QUERYABLE);
  //LOGREAD_PREFETCH 5->40
  ptr[40] = initParmBool(LOGREAD_PREFETCH, "ASNPLACEHOLDER", 0, 
                         ASNFALSE, ASN_NON_QUERYABLE);
  //WARNTXSZ 41->6
  ptr[41] = initParmInt(COMMIT_INTERVAL,   "ASNPLACEHOLDER", 2,
                        DefMin,
                        DefMax,
                        DefCommitInterval,
                        ASN_NON_QUERYABLE);
  ptr[42] = initParmString(COMPATIBILITY,  "ASNPLACEHOLDER", 0,
                          DefCompatibility, 0, ASN_NON_QUERYABLE);
  ptr[43] = initParmInt(WARNLOGAPI,"WARNLOGAPI", 0, 0, DefMax, 0, ASN_QUERYABLE_ALWAYS);
  //  Comment out LOG_COMMIT_INTERVAL parm which is not contained in current code release
/*
  ptr[44] = initParmInt(LOG_COMMIT_INTERVAL, "ASNPLACEHOLDER", 9,
                        0,
                        DefMax,
                        DefCommitInterval,
                        ASN_NON_QUERYABLE);
*/
} // end initDefaultparms

//------------------------------------------------------------------------------
//
// Function Name: SIGINT_handler
//
// Descriptive-name: the SIGNINT handler.
//
// Function: Signal handler for SIGINT. When SIGINT is received, the mark of 
//           stopping running is set. This is not for DB2 z/OS version.
//
//------------------------------------------------------------------------------
extern "C" void SIGINT_handler (int signum)
{
  timeToQuit = 1;
}

//------------------------------------------------------------------------------
// Function Name: addInterestedTables
//
// Descriptive-name: add interested tables whose log data are read by WPC.
//
// Function: Add interested tables to the log reader.
//
// Syntax: addInterestedTables ( conn,       // The database connection
//                               logrdr,     // The log reader
//                               predicate ) // The predicate to select table
//
// Return:   AsnRcOK   The tables are successfully added into the log reader.
//
//------------------------------------------------------------------------------
int addInterestedTables(dbConn* conn, logReaderClient* logrdr, char* predicate)
{
  int rc = AsnRcOk;
  char funcName[] = "addInterestedTables";
  int tableCount = 0;
  
  std::list<dbTable*> &dbTables 
    = TransPatternCBMgr::getInstance().dbTables;
  std::list<dbTable*> &noDCCDbTables
    = TransPatternCBMgr::getInstance().noDCCDbTables;
  
  char tabFormatBuf[5000];
  
  sqlStmtInfoType stmtInfo;
  sqlStmtHandle* hndl = NULL;
  sqlStmtMgr*     stmtMgr = conn->getSqlStmtMgr();
  
  snapDA OUTDA(4, varcharVal(MAX_TAB_SCHEMA), // CREATOR
                  varcharVal(MAX_TAB_NAME),   // NAME
                  charVal(1),                 // TYPE
                  charVal(1));                // DATA_CAPTURE
                  
  varTabSchema selTabSchema;
  varTabName   selTabName;
  char type = ' ';
  char dataCapture = 'N';

  
  OUTDA.setDA(1, (void*)&selTabSchema); 
  OUTDA.setDA(2, (void*)&selTabName);
  OUTDA.setDA(3, (void*)&type);
  OUTDA.setDA(4, (void*)&dataCapture);

#ifdef OS_ZOS
  char getTablesSQL[] = "SELECT STRIP(CREATOR), STRIP(NAME), TYPE, DATACAPTURE "
                         " FROM SYSIBM.SYSTABLES "
                         " WHERE %s %s %s ORDER BY CREATOR ASC, NAME ASC";

  char extraRestrictedTables[] = " CREATOR NOT LIKE 'SYS%' "
                                 " AND NAME NOT LIKE 'IBMQREP%' "
                                 " AND NAME NOT LIKE 'IBMSNAP%' "
                                 " AND TYPE='T' ";
#else  
  char getTablesSQL[] = "SELECT TRIM(TABSCHEMA), TRIM(TABNAME), TYPE, DATACAPTURE "
                         " FROM  SYSCAT.tables  "
                         " WHERE %s %s %s ORDER BY TABSCHEMA ASC, TABNAME ASC";

  char extraRestrictedTables[] = " TABSCHEMA NOT LIKE 'SYS%' "
                                 " AND TABNAME NOT LIKE 'IBMQREP%' "
                                 " AND TABNAME NOT LIKE 'IBMSNAP%'";
#endif //OS_ZOS
                                                
  ossSnprintf(tabFormatBuf, sizeof(tabFormatBuf), getTablesSQL, 
              predicate, 
              strlen(predicate) > 0 ? "AND" : "", 
              extraRestrictedTables);

  printf("INFO Query from catalog:%s\n", tabFormatBuf);
  
  if (pAsnParm->getBool(DEBUG))
  {
    printf("INFO Fetching with predicate %s\n", predicate);
  }
  
  int tablecount = 0;  
  while (!rc)
  {
    rc = stmtMgr->execFetch(tabFormatBuf, &hndl, stmtInfo, *OUTDA.getDA());   
    
    if (!rc)
    { 
      printf( "INFO Get one table. %.*s.%.*s\n", 
              selTabSchema.len,
              selTabSchema.buffer, 
              selTabName.len,
              selTabName.buffer);
   
      dbTable* newdbTable = new dbTable( *logrdr, 
                                         selTabSchema, 
                                         selTabName, 
                                         type, 
                                         dataCapture, 
                                         rc);
        
      if (!rc)
      {
        dbTables.push_front(newdbTable);
      }
      else if (rc == AsnRcWarnNoCDC)
      {
        noDCCDbTables.push_front(newdbTable);    
        rc = AsnRcOk;    
      }
      else
      {
        printf("ERROR Creat new database table.%d\n", rc);
        trcbackMsg(funcName, "new dbTable", rc, NULL);
      }
    }
    else 
    {
      if (rc != AsnRcWarnNoRow)
      {
#ifdef OS_ZOS
        printf("ERROR Fetching tables from SYSTABLES.%d\n",rc);
        trcbackMsg(funcName, "SELECT(SYSIBM.SYSTABLES)", rc, NULL);
#else
        trcbackMsg(funcName, "SELECT(SYSCAT.TABLES)", rc, NULL);
#endif //OS_ZOS
      }
    }
  } // end fetch from SYSCAT.TABLES/SYSIBM.SYSTABLES
  
  if (rc == AsnRcWarnNoRow)
  {
    printf("WARN no more rows.\n");
    rc = AsnRcOk;
  }
  
  if (!rc)
  {
    //
    // TODO - printed table output could be nicer
    // 
    char tabListMsg[500];
    
    if (dbTables.size() == 0 && noDCCDbTables.size() == 0)
    {
      ossSnprintf(tabListMsg, sizeof(tabListMsg), "No tables were found to monitor");
      pML->putAsnMsg( AsnMsg8999, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL, tabListMsg );  
      rc = AsnRcReqNotExist;
      printf("ERROR No tables were found to monitor.\n");
      goto exit;
    }
    
    if (dbTables.size() == 0)
    {
      ossSnprintf(tabListMsg, sizeof(tabListMsg), "No tables with DCC were found");
      pML->putAsnMsg( AsnMsg8999, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL, tabListMsg );  
      printf("WARN No tables with DCC were found.\n");
    }
    else
    {     
      ossSnprintf( tabListMsg, sizeof(tabListMsg), 
                   "The following "OSS_PRIdSZT" tables will be monitored:", 
                   dbTables.size());

      pML->putAsnMsg( AsnMsg8999, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL, tabListMsg );  
 
      printf( "INFO The following %d tables will be monitored.\n", 
              dbTables.size());
 
      for (std::list<dbTable*>::iterator it = dbTables.begin(); it!=dbTables.end(); ++it)
      {
        dbTable* table = *it;
        
        logrdr->insertIntoHash(table);

        table->toString(tabFormatBuf, sizeof(tabFormatBuf));
        printf("INFO %s\n", tabFormatBuf);
      }
    }

    if (noDCCDbTables.size() > 0)
    {
      ossSnprintf( tabListMsg, sizeof(tabListMsg), 
                   "The following "OSS_PRIdSZT" tables will not be monitored"
                   " until DCC is enabled:", 
                   noDCCDbTables.size());

      pML->putAsnMsg( AsnMsg8999, MLD_STDOUT | MLD_DIAGLOG, funcName, NULL, tabListMsg );    

      printf( "INFO The following %d tables will not be monitored"
              " until DCC is enabled:",
              noDCCDbTables.size());
      
      for (std::list<dbTable*>::iterator it = noDCCDbTables.begin(); 
           it!=noDCCDbTables.end(); 
           ++it)
      {
        dbTable* table = *it;
        
        table->toString(tabFormatBuf, sizeof(tabFormatBuf));
        printf("INFO %s\n", tabFormatBuf);
      }
    }
  }
  else if (rc && stmtInfo.errorCode)
  {
#ifndef OS_ZOS 
    conn->dbMsg(funcName, "SYSCAT.TABLES", "SELECT", stmtInfo, All);  
#else
    conn->dbMsg(funcName, "SYSIBM.SYSTABLES", "SELECT", stmtInfo, ALL);
#endif //OS_ZOS
  }
  else if (rc)
  {
    trcbackMsg(funcName, "execFetch", rc, NULL);
  }
 exit:
  return rc;
}

