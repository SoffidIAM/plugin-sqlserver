
// Copyright (c) 2000 Govern  de les Illes Balears
package com.soffid.iam.agent.oracle;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.Properties;

import es.caib.seycon.ng.comu.Dispatcher;
import es.caib.seycon.ng.comu.DispatcherAccessControl;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.util.TimedProcess;
import es.caib.seycon.UnknownUserException;
import es.caib.seycon.ng.comu.ControlAcces;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
import es.caib.seycon.ng.exception.UnknownRoleException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AccessControlMgr;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.RoleInfo;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserInfo;
import es.caib.seycon.ng.sync.intf.UserMgr;
import es.caib.seycon.db.LogInfoConnection;

/**
 * Agente SEYCON para gestionar bases de datos Oracle
 * <P>
 * @author $Author: u88683 $
 * @version $Revision: 1.5 $
 */


// $Log: OracleAgent.java,v $
// Revision 1.5  2012-06-20 08:21:36  u88683
// afegim ()
//
// Revision 1.4  2012-06-13 13:01:40  u88683
// - Nous usuaris: propaguem la contrasenya (OracleAgent, OracleCitaPrevia, OracleDesarrAgent)
// - Ho fem compatible amb seycon-base-4.0.4 (nous paquets)
//
// Revision 1.3  2012-05-16 11:26:42  u88683
// - Afegim condici� al triger de logoff per a programa (com a logon)
// - Correcci� per guardar usuaris que tenen atorgat un rol en SC_OR_ROLE
// - Fem que en UpdateRole s'inserisquen els usuaris que tenen actualment atorgat el rol en SC_OR_ROLE
//
// Revision 1.2  2012-05-03 09:04:48  u88683
// afegim condició per a programa en el logoff i 
// fem que es guarden els usuaris q tenen el rol atorgat en sc_or_role
//
// Revision 1.1  2012-02-21 08:14:18  u88683
// Seycon-base plugins - primera versi�
//
// Revision 1.25  2012-01-26 13:15:02  u88683
// Fem correccions a l'agent oracle:
// - sac_session_id de SC_OR_ACCLOG  pasa a ser varchar
// - fem correcci� en l'obtenci� del programa detectat a oracle 10 (pot obtindre m�s d'una filera)
//
// Revision 1.24  2011-12-27 10:30:43  u88683
// Correcci� Oracle 9: al obtenir el programa s'obtenen m�s d'una filera (cas de procesos interns de oracle - l'usuari �s nul), afegim condici� per evitar errors (username is not null)
// Desactivem els triggers abans de actualitzar-los (quan �s una nova versi�)
//
// Revision 1.23  2011-12-02 13:38:02  u88683
// Afegim control de versi� del control d'acc�s mitjan�ant la taula SC_OR_VERSIO i la variabla VERSIO.
//
// Ajustem tamany de les columnes de les taules de control d'acc�s a petici� de BBDDs
//
// Fem correcci� de programa en el logogg_audit_trigger (compatibilitat oracle 9).
//
// Fem que el estat d'activitat del control d'acc�s es verifique al inici (si �s actiu o no) de l'agent
//
// Revision 1.23  2011-12-02 12:36:33  u88683
// Guardem a la taula SC_OR_VERSIO la versió dels triggers (per poder fer
// actualització del codi dels triggers només quan calgui). 
// Es canvia el tamany de les columnes de les taules a un tamany proposat per BBDDs
//
// Revision 1.22  2011-11-08 12:53:42  u88683
// Fem q la  obtenci� del programa siga oracle9i-compatible (tamb� ho �s al 10g)
//
// Revision 1.21  2011-11-08 10:36:31  u88683
// correcci� en la regla del programa, pot �sser null, en aquest cas es sustitueix per ' ' (espai) perque faci match amb '%' (si existeix aquesta regla d'acc�s)
//
// Revision 1.20  2011-10-26 10:35:17  u88683
// Correcci� de crear collection a partir de array null
//
// Revision 1.19  2011-09-23 06:57:25  u88683
// *** empty log message ***
//
// Revision 1.18  2011-09-05 10:54:06  u88683
// Agent Oracle: fem que l'error on es mostra la consulta SQL siga compatible amb java 5
//
// Revision 1.17  2011-08-31 11:49:59  u88683
// Fem �s de la classe LogInfoPreparedStatement per obtindre el SQL que ha donat error en els logs
//
// Revision 1.16  2010-11-25 07:34:46  u88683
// Llancem InternalErrorException2 amb m�s info
//
// Revision 1.15  2010-11-24 14:01:54  u88683
// Fem que la taula SC_OR_ROLE s'empre encar aque no estiga actiu el control d�acc�s
//
// Revision 1.14  2010-10-05 11:15:56  u88683
// Canvis agent oracle (reduim llarg�ria columna)
//
// Revision 1.13  2010-09-20 08:19:32  u88683
// Canviem system.out per log.info/warn
//
// Revision 1.12  2010-09-09 07:42:17  u88683
// Obtenci� de logs: correcci� en l'obtencio de la data. Es canvia per un Timestamp
//
// Revision 1.11  2010-09-08 12:31:41  u88683
// restricci� de files per resultats i posem data de logoff en logon-denied
//
// Revision 1.10  2010-09-08 07:57:28  u88683
// *** empty log message ***
//
// Revision 1.9  2010-09-08 07:41:49  u88683
// Actualitzaci� dels registres d'acc�s (control d'acc�s)
//
// Revision 1.8  2010-09-07 10:53:48  u88683
// fem que s'obtingen <=100 registres cada vegada
//
// Revision 1.7  2010-09-07 10:37:21  u88683
// Fem que l'agent d'oracle implemente AccessLogMgr
//
// Revision 1.6  2010-09-06 08:31:29  u88683
// Añadimos el interfaz AccessLogMgr para poder distribuir los logs
//
// Revision 1.5  2010-09-02 06:09:47  u88683
// Control d'accés
//
// Revision 1.4  2010-08-11 12:51:16  u88683
// Gestión del ControlAccés
//
// Revision 1.4 2010-07-28 08:30:00 u88683
// Añadimos el interfaz AccessControlMgr para implementar las reglar de control de acceso
//
// Revision 1.3  2010-03-18 13:27:42  u88683
// Fem que quan es crea un nou rol a la base de dades, es faga un revoke per a l'usuari SYSTEM (per tal de no superar el màxim de rols que pot tindre un usuari a oracle [148])
//
// Revision 1.2  2008-06-12 08:02:51  u07286
// Backport agost 2008
//
// Revision 1.8  2007-08-13 12:11:24  u07286
// Mejorar devolucion de conexiones [#24]
//
// Revision 1.7  2007-06-13 12:32:42  u07286
// Corregido bug [#24]
//
// Revision 1.6  2005-08-10 08:37:13  u07286
// Cambiado mecanismo de confianza en el servidor
//
// Revision 1.5  2004/08/23 11:00:14  u07286
// *** empty log message ***
//
// Revision 1.4  2004/08/20 11:25:00  u07286
// Soporte Domino 6.5.1
//
// Revision 1.3  2004/03/15 12:08:04  u07286
// Conversion UTF-8
//
// Revision 1.2  2004/03/15 11:57:48  u07286
// Agregada documentacion JavaDoc
//

public class OracleAgent extends Agent implements UserMgr, RoleMgr, AccessControlMgr, AccessLogMgr
{
  /** Usuario Oracle */
  transient String user;
  /** Contraseña oracle */
  transient Password password;
  /** Cadena de conexión a la base de datos */
  transient String db;
  /** Contraseña con la que proteger el rol */
  transient Password rolePassword;
  /** Hash de conexiones ya establecidas. De esta forma se evita que el 
   * agente seycon abra conexiones sin control debido a problemas de 
   * comunicaciones con el servidor
   */
  static Hashtable hash = new Hashtable ();
  
  /* versió dels triggers del control d'accés */
  private final static String VERSIO = "1.2";
  
  
  /**
   * Constructor
   * @param params vector con parámetros de configuración:
   * <LI>0 = usuario</LI>
   * <LI>1 = contraseña oracle</LI>
   * <LI>2 = cadena de conexión a la base de datos</LI>
   * <LI>3 = contraseña con la que se protegerán los roles</LI>
   */
  public OracleAgent()
         throws java.rmi.RemoteException
  {
	 super();
  }
  
	/**
	 * Crea las tablas y los triggers (deshabilitados) de control de acceso
	 * @throws java.rmi.RemoteException
	 * @throws es.caib.seycon.InternalErrorException
	 */
	private void createAccessControl() throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			// SC_OR_ACCLOG: tabla de logs
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_ACCLOG'");
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				int anyo = Calendar.getInstance().get(Calendar.YEAR);
				// La creamos PARTICIONADA para el año actual
				String cmd = "create table SC_OR_ACCLOG  ( " +
						"   sac_user_id		varchar2(50 CHAR)," +
						"   sac_session_Id	varchar2(50 CHAR)," +
						"   sac_process		varchar2(50 CHAR)," +
						"   sac_host		varchar2(50 CHAR)," +
						"   sac_logon_day	date," +
						"   sac_os_user		varchar2(50 CHAR)," +
						"   sac_program		varchar2(80 CHAR)" + 
						" ) " +
						" partition by range (sac_logon_day) " +
						" ( " +
						"   partition SC_OR_ACCLOG_p"+anyo+" values less than (to_date('01/01/"+(anyo+1)+"','DD/MM/YYYY')), " +
						"   partition SC_OR_ACCLOG_otros values less than (maxvalue) " +
						" )";
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Creada tabla SC_OR_ACCLOG año {}", anyo, null);
			}
			rsetCAC.close();
			stmtCAC.close();
			
			
			// SC_OR_CONACC
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_CONACC'");
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_CONACC  ( " +
						"  SOC_USER VARCHAR2(50 CHAR) " +
						", SOC_ROLE VARCHAR2(50 CHAR) " +
						", SOC_HOST VARCHAR2(50 CHAR)"  +
						", SOC_PROGRAM VARCHAR2(80 CHAR) " +
						", SOC_CAC_ID  NUMBER(10,0) " +
						", SOC_HOSTNAME  VARCHAR2(50 CHAR) " +
						")";
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Creada tabla SC_OR_CONACC", null, null);
			}
			rsetCAC.close();
			stmtCAC.close();
			
			// SC_OR_ROLE
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_ROLE'");
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_ROLE  ( "
						+ "  	SOR_GRANTEE VARCHAR2(50 CHAR) NOT NULL "
						+ " 	, SOR_GRANTED_ROLE VARCHAR2(50 CHAR) NOT NULL "
						+ "	, CONSTRAINT SC_OR_ROLE_PK PRIMARY KEY "
						+ "  	( SOR_GRANTEE, SOR_GRANTED_ROLE ) ENABLE " 
						+ ")";
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Creada tabla SC_OR_ROLE", null, null);
			}
			rsetCAC.close();
			stmtCAC.close();
			
			// SC_OR_VERSIO
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_VERSIO'");
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_VERSIO  ( "
						+ "  SOV_VERSIO VARCHAR2(20 CHAR) "
						+ ", SOV_DATA DATE DEFAULT SYSDATE " + ")";
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Creada tabla SC_OR_VERSIO", null, null);
			}
			rsetCAC.close();
			stmtCAC.close();		

			
			// Ací comprovem que la versió dels triggers corresponga amb la versió actual
			boolean actualitzaTriggers = false; // Per defecte NO s'actualitzen
			// obtenim la darrera versió del trigger
			stmtCAC = sqlConnection
					.prepareStatement("select SOV_VERSIO from SC_OR_VERSIO where sov_data = (select max(SOV_DATA) from SC_OR_VERSIO)");
			rsetCAC = stmtCAC.executeQuery();
			
			// Mirem si no existeix cap fila o si la versió és diferent a la actual
			if (!rsetCAC.next()) {
				// No existeix cap, actualitzem i inserim una fila
				actualitzaTriggers = true;
				String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)";
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.setString(1, VERSIO);
				stmt.execute();
				stmt.close();		
				log.info("Detectada versió de l'agent diferent, s'actualitzen els triggers", null, null);
			} else {
				String versioActual = rsetCAC.getString(1);
				if (!VERSIO.equals(versioActual)) {
					// És una versió diferent, l'hem d'actualitzar
					actualitzaTriggers = true;
					// Guardem la versió actual
					String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)";
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.setString(1, VERSIO);
					
					stmt.execute();
					stmt.close();
					log.info("Detectada versió de l'agent diferent, s'actualitzen els triggers", null, null);
				}
			}
			rsetCAC.close();
			stmtCAC.close();		

			

			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'");
			rsetCAC = stmtCAC.executeQuery();
			
			boolean existeLogonTrigger = rsetCAC.next();

			if (!existeLogonTrigger || actualitzaTriggers) {
				
				if (existeLogonTrigger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection.prepareStatement("alter trigger logon_audit_trigger disable");
					stmt.execute();
					stmt.close();
					log.info("Desactivamos LOGON_AUDIT_TRIGGER para actualizarlo", null, null);					
				}
				
				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace TRIGGER logon_audit_trigger AFTER logon ON database \n" +
						"  DECLARE \n" +
						"    seycon_accesscontrol_exception exception; \n" +
						"    usuari                         VARCHAR2(2048); \n" +
						"    programa                       VARCHAR2(2048); \n" +
						"    p_host                         VARCHAR2(2048); \n" +
						"    osuser                         VARCHAR2(2048); \n" +
						"    process                        VARCHAR2(2048); \n" +
						"    sessionid                      VARCHAR2(2048); \n" +
						"    ipaddress                      VARCHAR2(2048); \n" +
						"    existe                         INTEGER; \n" +
						"   begin \n" +
						"     /* NO FEM LOG DE L'USUARI SYS A LOCALHOST */ \n" +
						"    --   if (UPPER(USUARI) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n" +
						" \n" +
						"    /*OBTENEMOS PARAMETROS DEL USUARIO*/ \n" +
						"    select user into USUARI from DUAL; \n" +
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') INTO IPADDRESS FROM DUAL; \n" +
						"    select nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1); \n" +
						"    SELECT SYS_CONTEXT('USERENV','OS_USER') INTO osuser from dual; \n" +
						"    select SYS_CONTEXT('USERENV','SESSIONID') into SESSIONID from DUAL; \n" +
						" \n" +
						"     /*VERIFICAMOS ENTRADA: */ \n" +
						"    if (UPPER(USUARI) in ('SYS','SYSTEM')) then EXISTE:=1; /*PROCESOS DE ESTOS USUARIOS (SIN SER DBA)*/ \n" +
						"    else \n" +
						"      select COUNT(*) INTO EXISTE from sc_or_conacc \n" +
						"      where ( soc_user is null or upper(usuari) like upper(soc_user)) \n" +
						"       and \n" +
						"      ( soc_role is null \n" +
						"        OR EXISTS \n" +
						"        (select 1 from sc_or_role where sor_grantee=usuari and sor_granted_role = soc_role) \n" +
						"      ) \n" +
						"      and (IPADDRESS like SOC_HOST) and (UPPER(PROGRAMA) like UPPER(SOC_PROGRAM)); \n" +
						"    END IF; \n" +
						" \n" +
						"    /* VERIFICAMOS ENTRADA*/ \n" +
						"    IF EXISTE=0 THEN \n" +
						"      savepoint START_LOGGING_ERROR; \n" +
						"      insert into SC_OR_ACCLOG ( \n" +
						"        SAC_USER_ID, \n" +
						"        SAC_SESSION_ID, \n" +
						"        SAC_PROCESS, \n" +
						"        SAC_HOST, \n" +
						"        SAC_LOGON_DAY, \n" +
						"        SAC_OS_USER, \n" +
						"        SAC_PROGRAM \n" +
						"      \n)" +
						" \n" +
						"      SELECT \n" +
						"        USUARI,     	/* user_id */ \n" +
						"        sessionid,     /* session_id */ \n" +
						"        'not-allowed', /* process */ \n" +
						"        ipaddress,     /* host */ \n" +
						"        Sysdate,       /* LOGON_DAY */ \n" +
						"        osuser,        /* OSUSER */ \n" +
						"        PROGRAMA       /* PROGRAM */ \n" +
						"      FROM dual; \n" +
						"      commit; \n" +
						"      Raise SEYCON_ACCESSCONTROL_EXCEPTION; \n" +
						"    ELSE \n" +
						"      /* registrem el logon correcte */ \n" +
						"      INSERT INTO SC_OR_ACCLOG ( \n" +
						"        SAC_USER_ID, \n" +
						"        SAC_SESSION_ID, \n" +
						"        SAC_PROCESS, \n" +
						"        SAC_HOST, \n" +
						"        SAC_LOGON_DAY, \n" +
						"        SAC_OS_USER, \n" +
						"        SAC_PROGRAM \n" +
						"      ) \n" +
						"      SELECT \n" +
						"        USUARI, 	/* user_id  */ \n" +
						"        sessionid, /* session_id */ \n" +
						"        'logon',   /* process */ \n" +
						"        ipaddress, /* host */ \n" +
						"        Sysdate,   /* LOGON_DAY */ \n" +
						"        osuser,    /* OSUSER */ \n" +
						"        Programa   /* PROGRAM */ \n" +
						"      FROM DUAL; \n" +
						"    end if; \n" +
						"  EXCEPTION \n" +
						"  when SEYCON_ACCESSCONTROL_EXCEPTION then \n" +
						"    RAISE_APPLICATION_ERROR (-20000, 'LOGON Error: You are not allowed to connect to this database '); \n" +
						"  END; \n";
				
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection.prepareStatement("alter trigger logon_audit_trigger disable");
				stmt.execute();
				stmt.close();
				log.info("Creado el trigger LOGON_AUDIT_TRIGGER y desactivado", null, null);
			}
			rsetCAC.close();
			stmtCAC.close();
			
			// LOGOFF
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_triggers where UPPER(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'");
			rsetCAC = stmtCAC.executeQuery();
			
			boolean existeLogoffTriger = rsetCAC.next();
			

			if (!existeLogoffTriger || actualitzaTriggers) {
				
				if (existeLogoffTriger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection.prepareStatement("alter trigger LOGOFF_AUDIT_TRIGGER disable");
					stmt.execute();
					stmt.close();
					log.info("Desactivamos LOGOFF_AUDIT_TRIGGER para actualizarlo", null, null);
				}				
				
				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace trigger LOGOFF_AUDIT_TRIGGER before logoff on database \n" +
						"  DECLARE \n" +
						"    USUARI   varchar2(2048); \n" +
						"    IPADDRESS      varchar2(2048); \n" +
						"	 programa       VARCHAR2(2048); \n" +
						"  BEGIN \n" +
						"    /* NO FEM LOG DE L'USUARI SYS A LOCALHOST */ \n" +
						"    --   if (UPPER(USUARI) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n" +
						" \n" +
						"    select user into USUARI from DUAL; \n" +
						"    /*  si es null, utilizamos el localhost */ \n" +
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') \n" +
						"      INTO IPADDRESS FROM DUAL; \n" +
						" \n" +
						"    SELECT nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1);" +
						" \n" +						
						"    INSERT INTO SC_OR_ACCLOG ( \n" +
						"      SAC_USER_ID, \n" +
						"      SAC_SESSION_ID, \n" +
						"      SAC_PROCESS, \n" +
						"      SAC_HOST, \n" +
						"      SAC_LOGON_DAY, \n" +
						"      SAC_OS_USER, \n" +
						"      SAC_PROGRAM \n" +
						"    ) \n" +
						"    SELECT \n" +
						"      usuari,                             /* user_id */ \n" +
						"      Sys_Context('USERENV','SESSIONID'), /* session_id */ \n" +
						"      'logoff',                           /* process */ \n" +
						"      IPADDRESS,                          /* host */ \n" +
						"      sysdate,                            /* LOGON_DAY */ \n" +
						"      SYS_CONTEXT('USERENV', 'OS_USER'),  /* OSUSER */ \n" +
						"      programa                            /* PROGRAM */ \n" +
						"    FROM DUAL; \n" +
						"  END; \n";
								
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection.prepareStatement("alter trigger LOGOFF_AUDIT_TRIGGER disable");
				stmt.execute();
				stmt.close();
				log.info("Creado el trigger LOGOFF_AUDIT_TRIGGER y desactivado", null, null);
			}
			rsetCAC.close();
			stmtCAC.close();			
			

			
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error creating access control", e);
		} finally {
			if (rsetCAC != null)
				try {
					rsetCAC.close();
				} catch (Exception e) {
				}
			if (stmtCAC != null)
				try {
					stmtCAC.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}

	}

  /** Inicializar el agente.

   */
	public void init() throws InternalErrorException {
		log.info("Iniciando Agente Oracle {}", getDispatcher().getCodi(),null);
	     user = getDispatcher().getParam0();
	     password = Password.decode(getDispatcher().getParam1());
	     db = getDispatcher().getParam2();
	     rolePassword = Password.decode(getDispatcher().getParam3());
		// Verifiramos que estén creadas las tablas y los triggers
		try {
			createAccessControl();
			// Obtenim les regles i activem els triggers si correspon
			updateAccessControl();
		} catch (Throwable th) {
			log.warn("Error en la verificació del control d'accés ", th);
			try {
				// Si hay error desactivamos los triggers (por si acaso)
				setAccessControlActive(false);
			} catch (Throwable tha) {}
		}

	}

  /** Liberar conexión a la base de datos.
   * Busca en el hash de conexiones activas alguna con el mismo nombre que el
   * agente y la libera.
   * A continuación la elimina del hash.
   * Se invoca desde el método de gestión de errores SQL.
   */
  public void releaseConnection () 
  {
    Connection conn = (Connection) hash.get (this.getDispatcher().getCodi());
    if (conn != null)
    {
      hash.remove (this.getDispatcher().getCodi());
      try { conn.close (); } catch (SQLException e) {}
    }
  }

  /** Obtener una conexión a la base de datos.
   * Si la conexión ya se encuentra establecida (se halla en el hash de
   * conexiones activas), simplemente se retorna al método invocante. Si no,
   * registra el driver oracle, efectúa la conexión con la base de datos y
   * la registra en el hash de conexiones activas
   * @return conexión SQL asociada.
   * @throws InternalErrorException algún error en el proceso de conexión
   */
  public Connection getConnection () throws InternalErrorException
  {
    Connection conn = (Connection) hash.get (this.getDispatcher().getCodi());
    if (conn == null)
    {
     try {
      DriverManager.registerDriver(new oracle.jdbc.driver.OracleDriver());
      // Connect to the database
      try {
    	  Properties props = new Properties(); 
    	  props.put("user", user); 
    	  props.put("password", password.getPassword());
    	  props.put("internal_logon", "sysdba"); 
    	  conn = DriverManager.getConnection (db, props);
      } catch (SQLException e) {
	      conn =
	 	         DriverManager.getConnection (db, user, password.getPassword ());
      }
      hash.put (this.getDispatcher().getCodi(), new LogInfoConnection(conn));
     } catch (SQLException e) {
      e.printStackTrace ();
      throw new InternalErrorException("Error connecting", e);
     } 
    }
    return conn;
  }

  /** Gestionar errores SQL.
   * Debe incovarse cuando se produce un error SQL.
   * Si el sistema lo considera oportuno cerrará la conexión SQL.
   * @param e Excepción oralce producida
   * @throws InternalErrorExcepción error que se debe propagar al servidor (si
   * es neceasario)
   */
  public void handleSQLException (SQLException e) throws InternalErrorException
  {
	  log.warn(this.getDispatcher().getCodi()+ " SQL Exception: ",e);
      if (e.getMessage().indexOf ("Broken pipe") > 0) {
        releaseConnection ();
      }
      if (e.getMessage().indexOf ("Invalid Packet") > 0) {
        releaseConnection ();
      }
      if (e.toString().indexOf ("ORA-01000") > 0) {
        releaseConnection ();
      }
      if (e.toString().indexOf ("Malformed SQL92") > 0) {
    	  e.printStackTrace(System.out);
        return;
      }
      e.printStackTrace (System.out);
  }  

  
  /** Actualizar los datos del usuario.
   * Crea el usuario en la base de datos y le asigna una contraseña aleatoria.
   * <BR>Da de alta los roles<BR>
   * Le asigna los roles oportuno.<BR>
   * Le retira los no necesarios.
   * @param user código de usuario
   * @throws java.rmi.RemoteException error de comunicaciones con el servidor
   * @throws InternalErrorException cualquier otro problema
   */
  public void updateUser(String codiCompte, Usuari usu) throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException
  {
	  //boolean active;
    TimedProcess p;
    String user = usu.getCodi();
    PreparedStatement stmt = null;
    PreparedStatement stmt2 = null;
    ResultSet rset = null;
//    String groupsConcat = "";
    Collection<RolGrant> roles;
    Collection<Grup> groups;
    
    String groupsAndRoles [];
    int i;
    
    // Control de acceso (tabla de roles)
    boolean cacActivo = false; // indica si está activo el control de acceso
    PreparedStatement stmtCAC = null;
    ResultSet rsetCAC = null;
    
    
    try {
      // Obtener los datos del usuario
      roles = getServer ().getAccountRoles(codiCompte, this.getDispatcher().getCodi());
      
      if (getDispatcher().getBasRol()) {
//        System.out.println (getName () + "Solo Roles");
        groups = null;
      } else {
//         System.out.println (getName () + "Roles y Grupos");
    	groups = getServer ().getUserGroups (usu.getId());
      }
      groupsAndRoles = concatUserGroupsAndRoles (groups, roles);
      
      Connection sqlConnection = getConnection ();
      
       	// Comprobamos que exista la tabla de roles de control de acceso
		stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'");
		rsetCAC = stmtCAC.executeQuery();

		if (rsetCAC.next()) {
			cacActivo = true; // la tabla existe (no miramos si está activo o no, nos da igual)
		}
		rsetCAC.close();
		stmtCAC.close();      
      
      // Comprobar si el usuario existe
      stmt = sqlConnection.prepareStatement (
                        "SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?");
      stmt.setString (1, user.toUpperCase());
      rset = stmt.executeQuery ();
      // Determinar si el usuario está o no activo
      // Si no existe darlo de alta
      if (! rset.next ())
      {
        stmt.close ();
        
		Password pass = getServer().getOrGenerateUserPassword(user, getDispatcher().getCodi());
        
        String cmd =  "CREATE USER \""+user.toUpperCase ()+"\" IDENTIFIED BY \""+
        		pass.getPassword()+"\" TEMPORARY TABLESPACE TEMP "+
				"DEFAULT TABLESPACE USERS ";
        stmt = sqlConnection.prepareStatement (cmd);
        stmt.execute ();
      }
//      System.out.println ("Usuario "+user+" ya existe");
      rset.close ();
      stmt.close ();
      // Dar o revocar permiso de create session : La part de revocar passada a removeUser()
        stmt = sqlConnection.prepareStatement (
           "GRANT CREATE SESSION TO  \""+user.toUpperCase ()+"\"");
        stmt.execute ();
        stmt.close ();
      
      // Eliminar los roles que sobran
      stmt = sqlConnection.prepareStatement (
            "SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?");
      stmt.setString (1, user.toUpperCase ());
      rset = stmt.executeQuery ();
      stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit
      while (rset.next())
      {
        boolean found = false;
        String role = rset.getString ( 1 );
        for ( i = 0; groupsAndRoles != null && ! found && i < groupsAndRoles.length ; i++)
        {
          if ( groupsAndRoles [ i ] != null && groupsAndRoles [ i ].equalsIgnoreCase ( role ) )
          {
            found = true;
            groupsAndRoles [ i ] = null;
          }
        }
        if (/*!active ||*/ ! found )
          stmt2.execute ("REVOKE \""+role+"\" FROM \""+user.toUpperCase ()+"\"");
      }
      rset.close ();
      stmt.close ();
      
      String rolesPorDefecto = null;
      // Crear los grupos si son necesarios
      for (Grup g: groups){
		  if(g!=null){
			  if(rolesPorDefecto == null)
				  rolesPorDefecto = "\""+g.getCodi().toUpperCase()+"\"";
			  else
				  rolesPorDefecto = rolesPorDefecto + ",\""+g.getCodi().toUpperCase()+"\"";
			  stmt = sqlConnection.prepareStatement (
			             "SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?");
			  stmt.setString (1, g.getCodi().toUpperCase ());
			  rset = stmt.executeQuery ();
			  if (!rset.next ())
	          {
	             // Password protected or not
	             stmt2.execute ("CREATE ROLE \""+g.getCodi().toUpperCase ()+"\"");
	             // Revoke a mi mismo
	             stmt2.execute ("REVOKE \""+g.getCodi().toUpperCase ()+"\" FROM \""+this.user.toUpperCase()+"\"");
	          }
	          rset.close ();
	          stmt.close ();  
		  }
      }
      
      // Crear los roles si son necesarios
      for(RolGrant r:roles){
    	  if(r!=null){
    		  //if(r.){
    		  if (rolesPorDefecto == null)
                  rolesPorDefecto = "\""+r.getRolName().toUpperCase ()+"\"";
                else
                  rolesPorDefecto = rolesPorDefecto + ",\"" +
                                    r.getRolName().toUpperCase () +"\"";
    		  //}
    		  stmt = sqlConnection.prepareStatement (
    		             "SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?");
    		  stmt.setString (1, r.getRolName().toUpperCase ());
    		  rset = stmt.executeQuery ();
    		  if (!rset.next ())
              {
                 // Password protected or not
                 String command = "CREATE ROLE \""+r.getRolName().toUpperCase ()+"\"";
                 if (getServer().getRoleInfo(r.getRolName(), r.getDispatcher()).getContrasenya())
                    command = command + " IDENTIFIED BY \""+
                              rolePassword.getPassword ()+"\"";
                 stmt2.execute (command);
                 // Revoke de mi mismo
                 stmt2.execute ("REVOKE \""+r.getRolName().toUpperCase ()+"\" FROM \""+this.user.toUpperCase()+"\"");
              }
              else
              {
                 String command = "ALTER ROLE \""+r.getRolName().toUpperCase ()+"\"";
                 if (getServer().getRoleInfo(r.getRolName(), r.getDispatcher()).getContrasenya())
                    command = command + " IDENTIFIED BY \""+
                              rolePassword.getPassword ()+"\"";
                 else
                    command = command + " NOT IDENTIFIED";
//                 System.out.println (command);
                 stmt2.execute (command);
              }
              rset.close ();
              stmt.close ();
    	  }
      }
      
      // Añadir los roles que no tiene
      for ( i = 0 ; /*active && */groupsAndRoles != null && i < groupsAndRoles.length; i++)
      {
        if (groupsAndRoles[i] != null)
        {
          stmt2.execute ("GRANT \""+groupsAndRoles[i].toUpperCase ()+"\" TO  \""+user.toUpperCase ()+"\"");
        }
      }

      // Ajustar los roles por defecto
     /* if (active)
      {*/
        if (rolesPorDefecto == null) rolesPorDefecto = "NONE";
        String ss = "ALTER USER \""+user.toUpperCase()+"\" DEFAULT ROLE "+
                     rolesPorDefecto;
//        System.out.println (ss);
        stmt2.execute (ss);
      /*}*/
      
      	// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si el usuario está activo??)
		if (true /*cacActivo*/) { // Lo activamos por defecto (para que no haya que propagar todos los usuarios)
			String[] grupsAndRolesCAC = concatUserGroupsAndRoles(groups, roles);
			HashSet grupsAndRolesHash = (grupsAndRolesCAC != null && grupsAndRolesCAC.length != 0) 
					? new HashSet(Arrays.asList(grupsAndRolesCAC)) // eliminem repetits 
					: new HashSet(); // evitem error al ésser llista buida
			grupsAndRolesCAC = (String[]) grupsAndRolesHash.toArray(new String[0]);
			// 1) Obtenemos los roles que ya tiene
			stmt = sqlConnection
					.prepareStatement("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?");
			stmt.setString(1, user.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual");
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; grupsAndRolesCAC != null && !found
						&& i < grupsAndRolesCAC.length; i++) {
					if (grupsAndRolesCAC[i] != null
							&& grupsAndRolesCAC[i].equalsIgnoreCase(role)) {
						found = true;
						grupsAndRolesCAC[i] = null;
					}
				}
				if (/*!active ||*/ !found) {
					stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='"
							+ user.toUpperCase()
							+ "' AND SOR_GRANTED_ROLE ='"
							+ role.toUpperCase() + "'");
					stmt2.close();
				}

			}
			rset.close();
			stmt.close();
			// Añadir los roles que no tiene
			if (/*active &&*/ grupsAndRolesCAC != null) for (i = 0;  i < grupsAndRolesCAC.length; i++) {
				if (grupsAndRolesCAC[i] != null) {
					stmt2 = sqlConnection.prepareStatement("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '"
							+ user.toUpperCase() + "', '" + grupsAndRolesCAC[i].toUpperCase() + "' FROM DUAL ");
					stmt2.execute();
					stmt2.close();
				}
			}

		}//FIN_CAC_ACTIVO
      
    } catch (SQLException e) {
      handleSQLException (e);
    } catch (Exception e) {
      e.printStackTrace ();
      throw new InternalErrorException("Error processing task", e);
    } finally {
      if (rset != null) try { rset.close(); } catch (Exception e) {}
      if (stmt != null) try { stmt.close(); } catch (Exception e) {}
      if (stmt2 != null) try { stmt2.close(); } catch (Exception e) {}
    }
  }

  /** Actualizar la contraseña del usuario.
   * Asigna la contraseña si el usuario está activo y la contraseña no es
   * temporal. En caso de contraseñas temporales, asigna un contraseña aleatoria.
   * @param user código de usuario
   * @param password contraseña a asignar
   * @param mustchange es una contraseña temporal?
   * @throws java.rmi.RemoteException error de comunicaciones con el servidor
   * @throws InternalErrorException cualquier otro problema
   */
  public void updateUserPassword(String user, Usuari arg1, Password password, boolean mustchange )
    throws es.caib.seycon.ng.exception.InternalErrorException
  {
    TimedProcess p;
    PreparedStatement stmt = null;
    String cmd = "";
    try {
      // Comprobar si el usuario existe
      Connection sqlConnection = getConnection ();
      stmt = sqlConnection.prepareStatement("SELECT USERNAME FROM SYS.DBA_USERS "+
              "WHERE USERNAME='"+user.toUpperCase()+"'");
      ResultSet rset = stmt.executeQuery ();
      if (rset.next() && password.getPassword (). length() > 0)
      {
         stmt.close ();
         cmd  ="ALTER USER \""+user.toUpperCase()+"\" IDENTIFIED BY \""+
                   password.getPassword()+"\"";
         stmt = sqlConnection.prepareStatement(cmd);         
         stmt.execute ();
      }
    } catch (SQLException e) {
      handleSQLException (e);
    }/* catch (UnknownUserException e) {
      if (stmt!=null) try {stmt.close();} catch (Exception e2) {}
    } */catch (Exception e ) {
      e.printStackTrace ();
      if (stmt!=null) try {stmt.close();} catch (Exception e2) {}
      throw new InternalErrorException("Error updating user password ", e);
    } finally {
        if (stmt != null) try { stmt.close(); } catch (Exception e) {}
    }
  }

  /** Validar contraseña. 
   * @param user código de usuario
   * @param password contraseña a asignar
   * @return false
   * @throws java.rmi.RemoteException error de comunicaciones con el servidor
   * @throws InternalErrorException cualquier otro problema
   */
  public boolean validateUserPassword(String user, Password password ) throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException
  {
    return false;
  }

  /** Concatenar los vectores de grupos y roles en uno solo.
   * Si el agente está basado en roles y no tiene ninguno, retorna el valor 
   * null
   * @param groups vector de grupos
   * @param roles vector de roles
   * @return vector con nombres de grupo y role
   */
   public String [] concatUserGroupsAndRoles (Collection<Grup> groups, Collection<RolGrant> roles)
   {
      int i;
      int j;
      
      if ( roles.isEmpty() && getDispatcher().getBasRol())  //roles.length == 0 && getRoleBased () 
        return null;
      LinkedList<String> concat = new LinkedList<String>();
      if (groups != null)
      {
    	  for (Grup g: groups)
    		  concat.add (g.getCodi());
      }
      for (RolGrant rg: roles)
      {
    	  concat.add(rg.getRolName());
      }
    		  
      return concat.toArray(new String[concat.size()]);
   }
   
   public String [] concatRoleNames (Collection<RolGrant> roles){
	   if (roles.isEmpty() && getDispatcher().getBasRol())
		   return null;
	   
	   LinkedList<String> concat = new LinkedList<String>();
	   for (RolGrant rg: roles){
		   concat.add(rg.getRolName());
	   }	
	   
	   return concat.toArray(new String[concat.size()]);
   }

/* (non-Javadoc)
 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String, java.lang.String)
 */
  public void updateRole(Rol ri) throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException{
	String bd = ri.getBaseDeDades();
	String role = ri.getNom();
    PreparedStatement stmt = null;
    String cmd = "";
    try {
      if ( this.getDispatcher().getCodi().equals(bd))
      {
	      // Comprobar si el rol existe en la bd
	      Connection sqlConnection = getConnection ();
	      stmt = sqlConnection.prepareStatement("SELECT ROLE FROM SYS.DBA_ROLES "+
	          "WHERE ROLE='"+role.toUpperCase()+"'");
	      ResultSet rset = stmt.executeQuery ();
	      if (! rset.next()) //aquest rol NO existeix com a rol de la BBDD
	      {
	      	if (ri != null) {//si el rol encara existeix al seycon (no s'ha esborrat)
	         stmt.close ();
	         cmd  ="CREATE ROLE \""+role.toUpperCase()+"\"";
	         
	         if ( ri.getContrasenya() )
	         {
	         	cmd = cmd + " IDENTIFIED BY \""+rolePassword.getPassword()+"\"";
	         }
	         stmt = sqlConnection.prepareStatement(cmd);
	         stmt.execute ();
	         // Fem un revoke per a l'usuari SYSTEM (CAI-579530: u88683)
	         stmt.close ();
	         stmt = sqlConnection.prepareStatement("REVOKE \""+role.toUpperCase()+"\" FROM \""+user.toUpperCase()+"\"");	         
	         stmt.execute ();
	         
	         // Aqui en no en tenim encara informació a la bbdd
	         // sobre qui té atorgat aquest rol.. no posem res a sc_or_role			
	      	}
	      }
	      else // ja existeix a la bbdd
	      {
	    	  if (ri != null){
				// Afegim informació dels usuaris que actualment tenen 
				// atorgat el rol a la bbdd (la info no és completa
				// però és consistent amb el rol de bbdd)
				// Ara inserim en SC_OR_ORACLE els usuaris q tinguen el rol a la base de dades
				String cmdrole = "INSERT INTO SC_OR_ROLE(SOR_GRANTEE, SOR_GRANTED_ROLE) "
						+ "SELECT GRANTEE, GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTED_ROLE= '"+role.toUpperCase()+"' MINUS "
						+ "SELECT SOR_GRANTEE, sor_granted_role FROM SC_OR_ROLE WHERE sor_granted_role='"+role.toUpperCase()+"'";
				stmt = sqlConnection.prepareStatement(cmdrole);
				stmt.execute();				
				stmt.close();
			}
	      }
	      stmt.close ();
	      rset.close();
      }
    } catch (SQLException e) {
      handleSQLException (e);
    } catch (Exception e ) {
      e.printStackTrace ();
      if (stmt!=null) try {stmt.close();} catch (Exception e2) {}
      throw new InternalErrorException("Error opdating role", e);
    }
}

	private void setAccessControlActive(boolean active) throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();
			// Activamos los triggers de logon y de loggoff
			String estado = active ? "ENABLE": "DISABLE";
			log.info("Control d'accés actiu? "+active, null, null);
			
			// LOGON
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'");
			rsetCAC = stmtCAC.executeQuery();
			
			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGON_AUDIT_TRIGGER "+estado;
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info ("Establim LOGON_AUDIT_TRIGGER com a "+estado,null,null);
			} else {
				log.warn("El trigger LOGON_AUDIT_TRIGGER no existe");
			}
			rsetCAC.close();
			stmtCAC.close();
			
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'");
			rsetCAC = stmtCAC.executeQuery();
			
			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGOFF_AUDIT_TRIGGER "+estado;
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info ("Establim LOGOFF_AUDIT_TRIGGER com a "+estado,null,null);
			} else {
				log.warn("El trigger LOGOFF_AUDIT_TRIGGER no existe");
			}
			rsetCAC.close();
			stmtCAC.close();	
			
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error access control active", e);
		} finally {
			if (rsetCAC != null)
				try {
					rsetCAC.close();
				} catch (Exception e) {
				}
			if (stmtCAC != null)
				try {
					stmtCAC.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
	}

	
	/**
	 * Nos permite comparar si una regla de control de acceso ya existe
	 * @param cac
	 * @param s_user
	 * @param s_role
	 * @param s_host
	 * @param s_program
	 * @param s_cac_id
	 * @return
	 */
	private boolean equalsControlAccess(ControlAcces cac, String s_user,
			String s_role, String s_host, String s_program, String s_cac_id) {
		
		// Si no es la misma fila, no continuamos (AÑADIDO POR TRAZAS)
		if (!s_cac_id.equals(cac.getId())) return false;	//idControlAcces canviat per getId
		
		// usuari o rol ha de ser nulo (uno de los dos)
		if (s_user == null) {
			if (cac.getUsuariGeneric() != null)
				return false;
		} else {
			if (!s_user.equals(cac.getUsuariGeneric())) return false;
		}
		if (s_role == null) {
			if (cac.getDescripcioRol() != null) return false;
		} else {
			if (!s_role.equals(cac.getDescripcioRol())) return false;
		}
		if (s_host == null) {
			if (cac.getIdMaquina() !=null) return false;	
		} else {
			if (!s_host.equals(cac.getIdMaquina())) return false;
		}
		if (s_program == null) {
			if (cac.getProgram() != null) return false;	
		} else {
			if (!s_program.equals(cac.getProgram())) return false;
		}
		
		return true; // Ha pasat totes les comprovacions 

	}	
	
	public void updateAccessControl() throws RemoteException,
			InternalErrorException {
		DispatcherAccessControl dispatcherInfo = null;	//Afegit AccessControl
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		try {
			dispatcherInfo = getServer().getDispatcherAccessControl(this.getDispatcher().getId());
			//dispatcherInfo = getServer().getDispatcherInfo(this.getDispatcher().getCodi());
			Connection sqlConnection = getConnection();

			if (dispatcherInfo == null) {
				setAccessControlActive(false); // desactivamos triggers
				throw new Exception("Error accessing DispatcherInfo ('"
						+ this.getDispatcher().getCodi() + "' - Disabling AccessControl");
			}
	
			if (dispatcherInfo.getControlAccessActiu()) { //getControlAccessActiu()
				// Lo activamos al final (!!)

				// Obtenemos las reglas de control de acceso
				LinkedList<ControlAcces> controlAcces = dispatcherInfo.getControlAcces();
				//ArrayList<ControlAccess> controlAccess = dispatcherInfo.getControlAcces();

				if (controlAcces == null || controlAcces.size() == 0) {
					// Eliminem les regles de control d'accés
					String cmd = "DELETE FROM SC_OR_CONACC";
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute(cmd);
					stmt.close();
				} else {
					stmt = sqlConnection
							.prepareStatement("SELECT SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM, SOC_CAC_ID from SC_OR_CONACC");
					rset = stmt.executeQuery();

					while (rset.next()) {
						boolean found = false;
						String s_user = rset.getString(1);
						String s_role = rset.getString(2);
						String s_host = rset.getString(3);
						String s_program = rset.getString(4);
						String s_idcac = rset.getString(5); // por id  ¿necesario?

						for (int i = 0; /* !found && */i < controlAcces.size(); i++) {
							ControlAcces cac = controlAcces.get(i);
							if (cac!=null && equalsControlAccess(cac, s_user, s_role,
									s_host, s_program, s_idcac)) {
								found = true; // ya existe: no lo creamos
								controlAcces.set(i, null);
							}
						}

						if (!found) {// No l'hem trobat: l'esborrem
							String condicions = "";
							// SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM
							if (s_user == null)
								condicions += " AND SOC_USER is null ";
							else
								condicions += " AND SOC_USER=? ";
							if (s_role == null)
								condicions += " AND SOC_ROLE is null ";
							else
								condicions += " AND SOC_ROLE=? ";
							stmt2 = sqlConnection
									.prepareStatement("DELETE SC_OR_CONACC WHERE SOC_HOST=? AND SOC_PROGRAM=? "
											+ condicions);
							stmt2.setString(1, s_host);
							stmt2.setString(2, s_program);
							int pos = 3;
							if (s_user != null)
								stmt2.setString(pos++, s_user);
							if (s_role != null)
								stmt2.setString(pos++, s_role);
							stmt2.execute();
							stmt2.close();
						}
					}
					rset.close();
					stmt.close();
					// añadimos los que no tiene
					for (int i = 0; i < controlAcces.size(); i++) {
						if (controlAcces.get(i) != null) {
							ControlAcces cac = controlAcces.get(i);
							stmt2 = sqlConnection
									.prepareStatement("INSERT INTO SC_OR_CONACC(SOC_USER, SOC_ROLE, SOC_HOST, SOC_PROGRAM, SOC_CAC_ID, SOC_HOSTNAME) VALUES (?,?,?,?,?,?)");
							stmt2.setString(1, cac.getUsuariGeneric());
							stmt2.setString(2, cac.getDescripcioRol()); 
							stmt2.setString(3, cac.getIpsPropagades());	
							stmt2.setString(4, cac.getProgram());
							stmt2.setString(5, cac.getId().toString());	
							stmt2.setString(6, cac.getNomMaquina());	
							stmt2.execute();
							stmt2.close();
						}
					}
				}
				// Los activamos tras propagar las reglas (!!)
				setAccessControlActive(true); // Activamos triggers

			} else { //Desactivamos los triggers
				setAccessControlActive(false); 
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error updating access control", e);
		} finally { // tamquem
			if (rset != null) {
				try {
					rset.close();
				} catch (Exception e) {
				}
			}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			if (stmt2 != null) {
				try {
					stmt2.close();
				} catch (Exception e) {
				}
			}
		}
	}

	public Collection<LogEntry> getLogFromDate(Date From) throws RemoteException,
			InternalErrorException {

		PreparedStatement stmt = null;
		ResultSet rset = null;
		//ArrayList<LogEntry> logs = new ArrayList<LogEntry>();
		Collection<LogEntry> logs = null;
		try {
			Connection sqlConnection = getConnection();
			// Obtenemos los logs
			String consulta = "select SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, "
					+ "SAC_LOGON_DAY, SAC_OS_USER, SAC_PROGRAM from SC_OR_ACCLOG ";

			if (From != null)
				consulta += "WHERE SAC_LOGON_DAY>=? ";
			consulta += " order by SAC_LOGON_DAY ";
			stmt = sqlConnection.prepareStatement(consulta);

			if (From != null)
				stmt.setTimestamp(1, new java.sql.Timestamp(From.getTime()));
			rset = stmt.executeQuery();
			String cadenaConnexio = db;
			int posArroba = cadenaConnexio.indexOf("@");
			int posDosPunts = cadenaConnexio.indexOf(":",posArroba);
			String hostDB = null;
			if (posArroba!=-1 && posDosPunts != -1)
				hostDB = cadenaConnexio.substring(posArroba+1,posDosPunts); // nombre del servidor
			if (hostDB == null || "localhost".equalsIgnoreCase(hostDB))
				hostDB = InetAddress.getLocalHost().getCanonicalHostName();
			while (rset.next() && logs.size()<=100) { // Limitem per 100 file
				LogEntry log = new LogEntry();
				log.setHost(hostDB);
				log.setProtocol("OTHER"); // De la tabla de serveis

				// Usuario S.O.
				log.setUser(rset.getString(6));
				log.SessionId = rset.getString(2);
				log.info = "dbUser: "+rset.getString(1)+ " Program: " + rset.getString(7); //7 = program
				String proceso = rset.getString(3);
				if ("logon".equalsIgnoreCase(proceso))
					log.type = LogEntry.LOGON;
				else if ("logoff".equalsIgnoreCase(proceso))
					log.type = LogEntry.LOGOFF;
				else if ("not-allowed".equalsIgnoreCase(proceso)) {
					log.type = LogEntry.LOGON_DENIED;
					log.info += " LOGON DENIED (Control d'accés)";
				}
				else
					log.type = -1; // desconocido
				log.setClient(rset.getString(4));
				log.setDate(rset.getTimestamp(5));
				 
				logs.add(log);
			}
			rset.close();
			stmt.close();
			return logs; //.toArray(new LogEntry[0]);
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error getting log", e);
		} finally {
			if (rset != null)
				try {
					rset.close();
				} catch (Exception e) {
				}
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}

		return null;
	}


	public void removeRole(String nom, String bbdd) {
		try{
			Connection sqlConnection = getConnection ();
			if ( this.getDispatcher().getCodi().equals(bbdd)){
				PreparedStatement stmtCAC = null;
				stmtCAC = sqlConnection.prepareStatement("DROP ROLE \"" + nom.toUpperCase() + "\"");
				stmtCAC.execute();
				stmtCAC.close();
				// Borramos las filas de control de acceso relacionadas
				// con el ROL
	
				ResultSet rsetCAC = null;
				try {
					stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'");
					rsetCAC = stmtCAC.executeQuery();
	
					if (rsetCAC.next()) { //Borramos referencias al rol en la tabla SC_OR_ROLE
						stmtCAC.close();
						stmtCAC = sqlConnection.prepareStatement("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTED_ROLE='"+ nom.toUpperCase() + "'");
						stmtCAC.execute();
						stmtCAC.close();
					}
				} finally {
					try {rsetCAC.close();} catch (Exception ex) {}
					try {stmtCAC.close();} catch (Exception ex) {}
				}
			}
		}catch(Exception e){
			e.printStackTrace();
		}
		
	}


	public void removeUser(String arg0) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try{
			Connection sqlConnection = getConnection ();
			PreparedStatement stmt = null;
	        stmt = sqlConnection.prepareStatement (
	           "REVOKE CREATE SESSION FROM \""+arg0.toUpperCase ()+"\"");
	        try {
	          stmt.execute ();
	        } catch (SQLException e) {
	        } finally {
	          stmt.close ();
	        }
	        // Borramos las referencias de la tabla de control de acceso
			if (true/* cacActivo*/) { // Lo activamos por defecto
				stmt = sqlConnection
						.prepareStatement("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='"
								+ arg0.toUpperCase() + "'");
				try {
					stmt.execute();
				} catch (SQLException e) {
				} finally {
					stmt.close();
				}
			}
		}catch(Exception e){
			e.printStackTrace();
			throw new InternalErrorException("Error removing user", e);
		}
	}

	public void updateUser(String nom, String descripcio) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		
		TimedProcess p;
	    PreparedStatement stmt = null;
	    PreparedStatement stmt2 = null;
	    ResultSet rset = null;

	    Collection<RolGrant> roles;
	    	    
	    int i;
	    
	    // Control de acceso (tabla de roles)
	    boolean cacActivo = false; // indica si está activo el control de acceso
	    PreparedStatement stmtCAC = null;
	    ResultSet rsetCAC = null;
	    
	    try {
	      // Obtener los datos del usuario
	      roles = getServer ().getAccountRoles(nom, this.getDispatcher().getCodi());
	      
	      Connection sqlConnection = getConnection ();
	      
	       	// Comprobamos que exista la tabla de roles de control de acceso
			stmtCAC = sqlConnection.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'");
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				cacActivo = true; // la tabla existe (no miramos si está activo o no, nos da igual)
			}
			rsetCAC.close();
			stmtCAC.close();      
	      
	      // Comprobar si el usuario existe
	      stmt = sqlConnection.prepareStatement (
	                        "SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?");
	      stmt.setString (1, nom.toUpperCase());
	      rset = stmt.executeQuery ();
	      // Determinar si el usuario está o no activo
	      // Si no existe darlo de alta
	      if (! rset.next ())
	      {
	        stmt.close ();
	        
			Password pass = getServer().getOrGenerateUserPassword(nom, getDispatcher().getCodi());
	        
	        String cmd =  "CREATE USER \""+nom.toUpperCase ()+"\" IDENTIFIED BY \""+
	        		pass.getPassword()+"\" TEMPORARY TABLESPACE TEMP "+
					"DEFAULT TABLESPACE USERS ";
	        stmt = sqlConnection.prepareStatement (cmd);
	        stmt.execute ();
	      }

	      rset.close ();
	      stmt.close ();
	      // Dar o revocar permiso de create session : La part de revocar passada a removeUser()
	        stmt = sqlConnection.prepareStatement (
	           "GRANT CREATE SESSION TO  \""+nom.toUpperCase ()+"\"");
	        stmt.execute ();
	        stmt.close ();
	      
	      // Eliminar los roles que sobran
	      stmt = sqlConnection.prepareStatement (
	            "SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?");
	      stmt.setString (1, nom.toUpperCase ());
	      rset = stmt.executeQuery ();
	      stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit
	      while (rset.next())
	      {
	        boolean found = false;
	        String role = rset.getString ( 1 );
	        
	        for (RolGrant ro:roles){
	        	if(ro != null && ro.getRolName().equalsIgnoreCase(role)){
	        		found = true;
	        		ro = null;
	        	}
	        }
	        if (!found)
	          stmt2.execute ("REVOKE \""+role+"\" FROM \""+nom.toUpperCase ()+"\"");
	      }
	      rset.close ();
	      stmt.close ();
	      
	      String rolesPorDefecto = null;
	      
	      // Crear los roles si son necesarios
	      for(RolGrant r:roles){
	    	  if(r!=null){
	    		  if (rolesPorDefecto == null)
	                  rolesPorDefecto = "\""+r.getRolName().toUpperCase ()+"\"";
	                else
	                  rolesPorDefecto = rolesPorDefecto + ",\"" + r.getRolName().toUpperCase () +"\"";
	    		  stmt = sqlConnection.prepareStatement("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?");
	    		  stmt.setString (1, r.getRolName().toUpperCase ());
	    		  rset = stmt.executeQuery ();
	    		  if (!rset.next ())
	              {
	                 // Password protected or not
	                 String command = "CREATE ROLE \""+r.getRolName().toUpperCase ()+"\"";
	                 if (getServer().getRoleInfo(r.getRolName(), r.getDispatcher()).getContrasenya())
	                    command = command + " IDENTIFIED BY \"" + rolePassword.getPassword ()+"\"";
	                 stmt2.execute (command);
	                 // Revoke de mi mismo
	                 stmt2.execute ("REVOKE \"" + r.getRolName().toUpperCase () + "\" FROM \"" + this.user.toUpperCase()+"\"");
	              }
	              else
	              {
	                 String command = "ALTER ROLE \"" + r.getRolName().toUpperCase () + "\"";
	                 if (getServer().getRoleInfo(r.getRolName(), r.getDispatcher()).getContrasenya())
	                    command = command + " IDENTIFIED BY \"" + rolePassword.getPassword () + "\"";
	                 else
	                    command = command + " NOT IDENTIFIED";
	                 stmt2.execute (command);
	              }
	              rset.close ();
	              stmt.close ();
	    	  }
	      }
	      
	      // Añadir los roles que no tiene
	      for (RolGrant ros:roles){
	    	  if(ros != null){
	    		  stmt2.execute ("GRANT \""+ros.getRolName().toUpperCase ()+"\" TO  \""+nom.toUpperCase ()+"\"");
	    	  }
	      }

	      // Ajustar los roles por defecto
	        if (rolesPorDefecto == null) 
	        	rolesPorDefecto = "NONE";
	        String ss = "ALTER USER \""+nom.toUpperCase()+"\" DEFAULT ROLE " + rolesPorDefecto;
	        stmt2.execute (ss);
	      
	      	// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si el usuario está activo??)
	        String[] rolesCAC = concatRoleNames(roles);
			HashSet grupsAndRolesHash = (rolesCAC != null && rolesCAC.length != 0) 
					? new HashSet(Arrays.asList(rolesCAC)) // eliminem repetits 
					: new HashSet(); // evitem error al ésser llista buida
			rolesCAC = (String[]) grupsAndRolesHash.toArray(new String[0]);
			// 1) Obtenemos los roles que ya tiene
			stmt = sqlConnection
				.prepareStatement("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?");
			stmt.setString(1, nom.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual");
			while (rset.next())
			{
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; rolesCAC != null && !found && i < rolesCAC.length; i++) {
					if (rolesCAC[i] != null && rolesCAC[i].equalsIgnoreCase(role)) {
							found = true;
							rolesCAC[i] = null;
					}
				}
				if (!found) {
					stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='"
							+ nom.toUpperCase()
							+ "' AND SOR_GRANTED_ROLE ='"
							+ role.toUpperCase() + "'");
					stmt2.close();
				}
			}
			rset.close();
			stmt.close();
			// Añadir los roles que no tiene
			if (rolesCAC != null) for (i = 0;  i < rolesCAC.length; i++) {
					if (rolesCAC[i] != null) {
						stmt2 = sqlConnection.prepareStatement("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '"
								+ nom.toUpperCase() + "', '" + rolesCAC[i].toUpperCase() + "' FROM DUAL ");
						stmt2.execute();
						stmt2.close();
					}
				} 
	    } catch (SQLException e) {
	      handleSQLException (e);
	    } catch (Exception e) {
	      e.printStackTrace ();
	      throw new InternalErrorException("Error updating user", e);
	    } finally {
	      if (rset != null) try { rset.close(); } catch (Exception e) {}
	      if (stmt != null) try { stmt.close(); } catch (Exception e) {}
	      if (stmt2 != null) try { stmt2.close(); } catch (Exception e) {}
	    }	
	}
}