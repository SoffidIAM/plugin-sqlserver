package com.soffid.iam.agent.oracle;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;
import java.util.Properties;

import es.caib.seycon.ng.comu.Account;
import es.caib.seycon.ng.comu.ControlAcces;
import es.caib.seycon.ng.comu.DispatcherAccessControl;
import es.caib.seycon.ng.comu.Grup;
import es.caib.seycon.ng.comu.Password;
import es.caib.seycon.ng.comu.Rol;
import es.caib.seycon.ng.comu.RolGrant;
import es.caib.seycon.ng.comu.Usuari;
//import es.caib.seycon.InternalErrorException;
import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.agent.Agent;
import es.caib.seycon.ng.sync.intf.AccessControlMgr;
import es.caib.seycon.ng.sync.intf.AccessLogMgr;
import es.caib.seycon.ng.sync.intf.LogEntry;
import es.caib.seycon.ng.sync.intf.ReconcileMgr2;
import es.caib.seycon.ng.sync.intf.RoleMgr;
import es.caib.seycon.ng.sync.intf.UserMgr;

/**
 * Agente SEYCON para gestionar bases de datos Oracle
 * <P>
 */

public class OracleAgent extends Agent implements UserMgr, RoleMgr,
		AccessControlMgr, AccessLogMgr, ReconcileMgr2 {
	/** Usuario Oracle */
	transient String user;
	/** Contraseña oracle */
	transient Password password;
	/** Cadena de conexión a la base de datos */
	transient String db;
	/** Contraseña con la que proteger el rol */
	transient Password rolePassword;
	/**
	 * Hash de conexiones ya establecidas. De esta forma se evita que el agente
	 * seycon abra conexiones sin control debido a problemas de comunicaciones
	 * con el servidor
	 */
	static Hashtable hash = new Hashtable();

	/* versió dels triggers del control d'accés */
	private final static String VERSIO = "1.2"; //$NON-NLS-1$

	/**
	 * Constructor
	 * 
	 * @param params
	 *            vector con parámetros de configuración: <LI>0 = usuario</LI>
	 *            <LI>1 = contraseña oracle</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
	 */
	public OracleAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Crea las tablas y los triggers (deshabilitados) de control de acceso
	 * 
	 * @throws java.rmi.RemoteException
	 * @throws es.caib.seycon.InternalErrorException
	 */
	private void createAccessControl() throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			// SC_OR_ACCLOG: tabla de logs
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_ACCLOG'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				int anyo = Calendar.getInstance().get(Calendar.YEAR);
				// La creamos PARTICIONADA para el año actual
				String cmd = "create table SC_OR_ACCLOG  ( " + //$NON-NLS-1$
						"   sac_user_id		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_session_Id	varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_process		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_host		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_logon_day	date,"
						+ //$NON-NLS-1$
						"   sac_os_user		varchar2(50 CHAR),"
						+ //$NON-NLS-1$
						"   sac_program		varchar2(80 CHAR)"
						+ //$NON-NLS-1$
//						" ) "
//						+ //$NON-NLS-1$
//						" partition by range (sac_logon_day) "
//						+ //$NON-NLS-1$
//						" ( "
//						+ //$NON-NLS-1$
//						"   partition SC_OR_ACCLOG_p"
//						+ anyo
//						+ " values less than (to_date('01/01/" + (anyo + 1) + "','DD/MM/YYYY')), " + //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
//						"   partition SC_OR_ACCLOG_otros values less than (maxvalue) "
//						+ //$NON-NLS-1$
						" )"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Created table 'SC_OR_ACCLOG', year {}", anyo, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_CONACC
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_CONACC'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_CONACC  ( " + //$NON-NLS-1$
						"  SOC_USER VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						", SOC_ROLE VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						", SOC_HOST VARCHAR2(50 CHAR)" + //$NON-NLS-1$
						", SOC_PROGRAM VARCHAR2(80 CHAR) " + //$NON-NLS-1$
						", SOC_CAC_ID  NUMBER(10,0) " + //$NON-NLS-1$
						", SOC_HOSTNAME  VARCHAR2(50 CHAR) " + //$NON-NLS-1$
						")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Created table 'SC_OR_CONACC'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_ROLE
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_ROLE'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_ROLE  ( " //$NON-NLS-1$
						+ "  	SOR_GRANTEE VARCHAR2(50 CHAR) NOT NULL " //$NON-NLS-1$
						+ " 	, SOR_GRANTED_ROLE VARCHAR2(50 CHAR) NOT NULL " //$NON-NLS-1$
						+ "	, CONSTRAINT SC_OR_ROLE_PK PRIMARY KEY " //$NON-NLS-1$
						+ "  	( SOR_GRANTEE, SOR_GRANTED_ROLE ) ENABLE " //$NON-NLS-1$
						+ ")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Created table 'SC_OR_ROLE'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_VERSIO
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where upper(table_name) ='SC_OR_VERSIO'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_VERSIO  ( " //$NON-NLS-1$
						+ "  SOV_VERSIO VARCHAR2(20 CHAR) " //$NON-NLS-1$
						+ ", SOV_DATA DATE DEFAULT SYSDATE " + ")"; //$NON-NLS-1$ //$NON-NLS-2$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info("Created table 'SC_OR_VERSIO'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// Ací comprovem que la versió dels triggers corresponga amb la
			// versió actual
			boolean actualitzaTriggers = false; // Per defecte NO s'actualitzen
			// obtenim la darrera versió del trigger
			stmtCAC = sqlConnection
					.prepareStatement("select SOV_VERSIO from SC_OR_VERSIO where sov_data = (select max(SOV_DATA) from SC_OR_VERSIO)"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			// Mirem si no existeix cap fila o si la versió és diferent a la
			// actual
			if (!rsetCAC.next()) {
				// No existeix cap, actualitzem i inserim una fila
				actualitzaTriggers = true;
				String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.setString(1, VERSIO);
				stmt.execute();
				stmt.close();
				log.info(
						"Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
			} else {
				String versioActual = rsetCAC.getString(1);
				if (!VERSIO.equals(versioActual)) {
					// És una versió diferent, l'hem d'actualitzar
					actualitzaTriggers = true;
					// Guardem la versió actual
					String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.setString(1, VERSIO);

					stmt.execute();
					stmt.close();
					log.info(
							"Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
				}
			}
			rsetCAC.close();
			stmtCAC.close();

			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogonTrigger = rsetCAC.next();

			if (!existeLogonTrigger || actualitzaTriggers) {

				if (existeLogonTrigger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection
							.prepareStatement("alter trigger logon_audit_trigger disable"); //$NON-NLS-1$
					stmt.execute();
					stmt.close();
					log.info(
							"Disabled 'LOGON_AUDIT_TRIGGER' to updated it", null, null); //$NON-NLS-1$
				}

				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace TRIGGER logon_audit_trigger AFTER logon ON database \n" + //$NON-NLS-1$
						"  DECLARE \n"
						+ //$NON-NLS-1$
						"    seycon_accesscontrol_exception exception; \n"
						+ //$NON-NLS-1$
						"    usuari                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    programa                       VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    p_host                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    osuser                         VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    process                        VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    sessionid                      VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    ipaddress                      VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"    existe                         INTEGER; \n"
						+ //$NON-NLS-1$
						"   begin \n"
						+ //$NON-NLS-1$
						"     /* NO FEM LOG DE L'USUARI SYS A LOCALHOST */ \n"
						+ //$NON-NLS-1$
						"    --   if (UPPER(USUARI) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    /*OBTENEMOS PARAMETROS DEL USUARIO*/ \n"
						+ //$NON-NLS-1$
						"    select user into USUARI from DUAL; \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') INTO IPADDRESS FROM DUAL; \n"
						+ //$NON-NLS-1$
						"    select nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1); \n"
						+ //$NON-NLS-1$
						"    SELECT SYS_CONTEXT('USERENV','OS_USER') INTO osuser from dual; \n"
						+ //$NON-NLS-1$
						"    select SYS_CONTEXT('USERENV','SESSIONID') into SESSIONID from DUAL; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"     /*VERIFICAMOS ENTRADA: */ \n"
						+ //$NON-NLS-1$
						"    if (UPPER(USUARI) in ('SYS','SYSTEM')) then EXISTE:=1; /*PROCESOS DE ESTOS USUARIOS (SIN SER DBA)*/ \n"
						+ //$NON-NLS-1$
						"    else \n"
						+ //$NON-NLS-1$
						"      select COUNT(*) INTO EXISTE from sc_or_conacc \n"
						+ //$NON-NLS-1$
						"      where ( soc_user is null or upper(usuari) like upper(soc_user)) \n"
						+ //$NON-NLS-1$
						"       and \n"
						+ //$NON-NLS-1$
						"      ( soc_role is null \n"
						+ //$NON-NLS-1$
						"        OR EXISTS \n"
						+ //$NON-NLS-1$
						"        (select 1 from sc_or_role where sor_grantee=usuari and sor_granted_role = soc_role) \n"
						+ //$NON-NLS-1$
						"      ) \n"
						+ //$NON-NLS-1$
						"      and (IPADDRESS like SOC_HOST) and (UPPER(PROGRAMA) like UPPER(SOC_PROGRAM)); \n"
						+ //$NON-NLS-1$
						"    END IF; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    /* VERIFICAMOS ENTRADA*/ \n"
						+ //$NON-NLS-1$
						"    IF EXISTE=0 THEN \n"
						+ //$NON-NLS-1$
						"      savepoint START_LOGGING_ERROR; \n"
						+ //$NON-NLS-1$
						"      insert into SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"        SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"        SAC_HOST, \n"
						+ //$NON-NLS-1$
						"        SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"        SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"        SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"      \n)"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"      SELECT \n"
						+ //$NON-NLS-1$
						"        USUARI,     	/* user_id */ \n"
						+ //$NON-NLS-1$
						"        sessionid,     /* session_id */ \n"
						+ //$NON-NLS-1$
						"        'not-allowed', /* process */ \n"
						+ //$NON-NLS-1$
						"        ipaddress,     /* host */ \n"
						+ //$NON-NLS-1$
						"        Sysdate,       /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"        osuser,        /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"        PROGRAMA       /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"      FROM dual; \n"
						+ //$NON-NLS-1$
						"      commit; \n"
						+ //$NON-NLS-1$
						"      Raise SEYCON_ACCESSCONTROL_EXCEPTION; \n"
						+ //$NON-NLS-1$
						"    ELSE \n"
						+ //$NON-NLS-1$
						"      /* registrem el logon correcte */ \n"
						+ //$NON-NLS-1$
						"      INSERT INTO SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"        SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"        SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"        SAC_HOST, \n"
						+ //$NON-NLS-1$
						"        SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"        SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"        SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"      ) \n"
						+ //$NON-NLS-1$
						"      SELECT \n"
						+ //$NON-NLS-1$
						"        USUARI, 	/* user_id  */ \n"
						+ //$NON-NLS-1$
						"        sessionid, /* session_id */ \n"
						+ //$NON-NLS-1$
						"        'logon',   /* process */ \n"
						+ //$NON-NLS-1$
						"        ipaddress, /* host */ \n"
						+ //$NON-NLS-1$
						"        Sysdate,   /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"        osuser,    /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"        Programa   /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"      FROM DUAL; \n"
						+ //$NON-NLS-1$
						"    end if; \n"
						+ //$NON-NLS-1$
						"  EXCEPTION \n"
						+ //$NON-NLS-1$
						"  when SEYCON_ACCESSCONTROL_EXCEPTION then \n"
						+ //$NON-NLS-1$
						"    RAISE_APPLICATION_ERROR (-20000, 'LOGON Error: You are not allowed to connect to this database '); \n"
						+ //$NON-NLS-1$
						"  END; \n"; //$NON-NLS-1$

				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection
						.prepareStatement("alter trigger logon_audit_trigger disable"); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				log.info(
						"Trigger 'LOGON_AUDIT_TRIGGER' created and disabled", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// LOGOFF
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_triggers where UPPER(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogoffTriger = rsetCAC.next();

			if (!existeLogoffTriger || actualitzaTriggers) {

				if (existeLogoffTriger && actualitzaTriggers) {
					// Lo desactivamos (para actualizarlo)
					stmt = sqlConnection
							.prepareStatement("alter trigger LOGOFF_AUDIT_TRIGGER disable"); //$NON-NLS-1$
					stmt.execute();
					stmt.close();
					log.info(
							"Disabled 'LOGOFF_AUDIT_TRIGGER' to update it", null, null); //$NON-NLS-1$
				}

				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create or replace trigger LOGOFF_AUDIT_TRIGGER before logoff on database \n" + //$NON-NLS-1$
						"  DECLARE \n"
						+ //$NON-NLS-1$
						"    USUARI   varchar2(2048); \n"
						+ //$NON-NLS-1$
						"    IPADDRESS      varchar2(2048); \n"
						+ //$NON-NLS-1$
						"	 programa       VARCHAR2(2048); \n"
						+ //$NON-NLS-1$
						"  BEGIN \n"
						+ //$NON-NLS-1$
						"    /* NO FEM LOG DE L'USUARI SYS A LOCALHOST */ \n"
						+ //$NON-NLS-1$
						"    --   if (UPPER(USUARI) IN ('SYS') AND IPADDRESS='127.0.0.1') THEN RETURN; END IF;\n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    select user into USUARI from DUAL; \n"
						+ //$NON-NLS-1$
						"    /*  si es null, utilizamos el localhost */ \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(SYS_CONTEXT('USERENV','IP_ADDRESS'),'127.0.0.1') \n"
						+ //$NON-NLS-1$
						"      INTO IPADDRESS FROM DUAL; \n"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    SELECT nvl(module,' ') INTO programa from v$session where audsid = userenv('sessionid') and username is not null and sid=(select SID from v$mystat where rownum=1);"
						+ //$NON-NLS-1$
						" \n"
						+ //$NON-NLS-1$
						"    INSERT INTO SC_OR_ACCLOG ( \n"
						+ //$NON-NLS-1$
						"      SAC_USER_ID, \n"
						+ //$NON-NLS-1$
						"      SAC_SESSION_ID, \n"
						+ //$NON-NLS-1$
						"      SAC_PROCESS, \n"
						+ //$NON-NLS-1$
						"      SAC_HOST, \n"
						+ //$NON-NLS-1$
						"      SAC_LOGON_DAY, \n"
						+ //$NON-NLS-1$
						"      SAC_OS_USER, \n"
						+ //$NON-NLS-1$
						"      SAC_PROGRAM \n"
						+ //$NON-NLS-1$
						"    ) \n"
						+ //$NON-NLS-1$
						"    SELECT \n"
						+ //$NON-NLS-1$
						"      usuari,                             /* user_id */ \n"
						+ //$NON-NLS-1$
						"      Sys_Context('USERENV','SESSIONID'), /* session_id */ \n"
						+ //$NON-NLS-1$
						"      'logoff',                           /* process */ \n"
						+ //$NON-NLS-1$
						"      IPADDRESS,                          /* host */ \n"
						+ //$NON-NLS-1$
						"      sysdate,                            /* LOGON_DAY */ \n"
						+ //$NON-NLS-1$
						"      SYS_CONTEXT('USERENV', 'OS_USER'),  /* OSUSER */ \n"
						+ //$NON-NLS-1$
						"      programa                            /* PROGRAM */ \n"
						+ //$NON-NLS-1$
						"    FROM DUAL; \n" + //$NON-NLS-1$
						"  END; \n"; //$NON-NLS-1$

				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				// Lo desactivamos
				stmt = sqlConnection
						.prepareStatement("alter trigger LOGOFF_AUDIT_TRIGGER disable"); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
				log.info("Trigger 'LOGOFF_AUDIT_TRIGGER' created and disabled",
						null, null);
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.AccessControlVerificationError"), e); //$NON-NLS-1$
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
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		log.info("Starting Oracle agent {}", getDispatcher().getCodi(), null); //$NON-NLS-1$
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
			log.warn("Error in the access control verification", th); //$NON-NLS-1$
			try {
				// Si hay error desactivamos los triggers (por si acaso)
				setAccessControlActive(false);
			} catch (Throwable tha) {
			}
		}

	}

	/**
	 * Liberar conexión a la base de datos. Busca en el hash de conexiones
	 * activas alguna con el mismo nombre que el agente y la libera. A
	 * continuación la elimina del hash. Se invoca desde el método de gestión de
	 * errores SQL.
	 */
	public void releaseConnection() {
		Connection conn = (Connection) hash.get(this.getDispatcher().getCodi());
		if (conn != null) {
			hash.remove(this.getDispatcher().getCodi());
			try {
				conn.close();
			} catch (SQLException e) {
			}
		}
	}

	/**
	 * Obtener una conexión a la base de datos. Si la conexión ya se encuentra
	 * establecida (se halla en el hash de conexiones activas), simplemente se
	 * retorna al método invocante. Si no, registra el driver oracle, efectúa la
	 * conexión con la base de datos y la registra en el hash de conexiones
	 * activas
	 * 
	 * @return conexión SQL asociada.
	 * @throws InternalErrorException
	 *             algún error en el proceso de conexión
	 */
	public Connection getConnection() throws InternalErrorException {
		Connection conn = (Connection) hash.get(this.getDispatcher().getCodi());
		if (conn == null) {
			try {
				DriverManager
						.registerDriver(new oracle.jdbc.driver.OracleDriver());
				// Connect to the database
				try {
					Properties props = new Properties();
					props.put("user", user); //$NON-NLS-1$
					props.put("password", password.getPassword()); //$NON-NLS-1$
					props.put("internal_logon", "sysdba"); //$NON-NLS-1$ //$NON-NLS-2$
					conn = DriverManager.getConnection(db, props);
				} catch (SQLException e) {
					conn = DriverManager.getConnection(db, user,
							password.getPassword());
				}
				hash.put(this.getDispatcher().getCodi(), conn);
			} catch (SQLException e) {
				e.printStackTrace();
				throw new InternalErrorException(
						Messages.getString("OracleAgent.ConnectionError"), e); //$NON-NLS-1$
			}
		}
		return conn;
	}

	/**
	 * Gestionar errores SQL. Debe incovarse cuando se produce un error SQL. Si
	 * el sistema lo considera oportuno cerrará la conexión SQL.
	 * 
	 * @param e
	 *            Excepción oralce producida
	 * @throws InternalErrorExcepción
	 *             error que se debe propagar al servidor (si es neceasario)
	 */
	public void handleSQLException(SQLException e)
			throws InternalErrorException {
		log.warn(this.getDispatcher().getCodi() + " SQL Exception: ", e); //$NON-NLS-1$
		if (e.getMessage().indexOf("Broken pipe") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		if (e.getMessage().indexOf("Invalid Packet") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		if (e.toString().indexOf("ORA-01000") > 0) { //$NON-NLS-1$
			releaseConnection();
		}
		if (e.toString().indexOf("Malformed SQL92") > 0) { //$NON-NLS-1$
			e.printStackTrace(System.out);
			return;
		}
		e.printStackTrace(System.out);
	}

	/**
	 * Actualizar los datos del usuario. Crea el usuario en la base de datos y
	 * le asigna una contraseña aleatoria. <BR>
	 * Da de alta los roles<BR>
	 * Le asigna los roles oportuno.<BR>
	 * Le retira los no necesarios.
	 * 
	 * @param user
	 *            código de usuario
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUser(String codiCompte, Usuari usu)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		// boolean active;
		String user = usu.getCodi();
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;
		// String groupsConcat = "";
		Collection<RolGrant> roles;
		Collection<Grup> groups;

		String groupsAndRoles[];
		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(codiCompte,
					this.getDispatcher().getCodi());

			if (getDispatcher().getBasRol()) {
				// System.out.println (getName () + "Solo Roles");
				groups = null;
			} else {
				// System.out.println (getName () + "Roles y Grupos");
				groups = getServer().getUserGroups(usu.getId());
			}
			groupsAndRoles = concatUserGroupsAndRoles(groups, roles);

			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				cacActivo = true; // la tabla existe (no miramos si está activo
									// o no, nos da igual)
			}
			rsetCAC.close();
			stmtCAC.close();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement("SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?"); //$NON-NLS-1$
			stmt.setString(1, user.toUpperCase());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (!rset.next()) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(user,
						getDispatcher().getCodi());

				String cmd = "CREATE USER \"" + user.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						pass.getPassword() + "\" TEMPORARY TABLESPACE TEMP " + //$NON-NLS-1$
						"DEFAULT TABLESPACE USERS "; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
			}
			// System.out.println ("Usuario "+user+" ya existe");
			rset.close();
			stmt.close();
			// Dar o revocar permiso de create session : La part de revocar
			// passada a removeUser()
			stmt = sqlConnection
					.prepareStatement("GRANT CREATE SESSION TO  \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?"); //$NON-NLS-1$
			stmt.setString(1, user.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit //$NON-NLS-1$
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; groupsAndRoles != null && !found
						&& i < groupsAndRoles.length; i++) {
					if (groupsAndRoles[i] != null
							&& groupsAndRoles[i].equalsIgnoreCase(role)) {
						found = true;
						groupsAndRoles[i] = null;
					}
				}
				if (/* !active || */!found)
					stmt2.execute("REVOKE \"" + role + "\" FROM \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;
			// Crear los grupos si son necesarios
			for (Grup g : groups) {
				if (g != null) {
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + g.getCodi().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto
								+ ",\"" + g.getCodi().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					stmt = sqlConnection
							.prepareStatement("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?"); //$NON-NLS-1$
					stmt.setString(1, g.getCodi().toUpperCase());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						// Password protected or not
						stmt2.execute("CREATE ROLE \"" + g.getCodi().toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$
						// Revoke a mi mismo
						stmt2.execute("REVOKE \"" + g.getCodi().toUpperCase() + "\" FROM \"" + this.user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					}
					rset.close();
					stmt.close();
				}
			}

			// Crear los roles si son necesarios
			for (RolGrant r : roles) {
				if (r != null) {
					// if(r.){
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto + ",\"" + //$NON-NLS-1$
								r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$
					// }
					stmt = sqlConnection
							.prepareStatement("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?"); //$NON-NLS-1$
					stmt.setString(1, r.getRolName().toUpperCase());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						// Password protected or not
						String command = "CREATE ROLE \"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						if (getServer().getRoleInfo(r.getRolName(),
								r.getDispatcher()).getContrasenya())
							command = command + " IDENTIFIED BY \"" + //$NON-NLS-1$
									rolePassword.getPassword() + "\""; //$NON-NLS-1$
						stmt2.execute(command);
						// Revoke de mi mismo
						stmt2.execute("REVOKE \"" + r.getRolName().toUpperCase() + "\" FROM \"" + this.user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					} else {
						String command = "ALTER ROLE \"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						if (getServer().getRoleInfo(r.getRolName(),
								r.getDispatcher()).getContrasenya())
							command = command + " IDENTIFIED BY \"" + //$NON-NLS-1$
									rolePassword.getPassword() + "\""; //$NON-NLS-1$
						else
							command = command + " NOT IDENTIFIED"; //$NON-NLS-1$
							// System.out.println (command);
						stmt2.execute(command);
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (i = 0; /* active && */groupsAndRoles != null
					&& i < groupsAndRoles.length; i++) {
				if (groupsAndRoles[i] != null) {
					stmt2.execute("GRANT \"" + groupsAndRoles[i].toUpperCase() + "\" TO  \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				}
			}

			// Ajustar los roles por defecto
			/*
			 * if (active) {
			 */
			if (rolesPorDefecto == null)
				rolesPorDefecto = "NONE"; //$NON-NLS-1$
			String ss = "ALTER USER \"" + user.toUpperCase() + "\" DEFAULT ROLE " + //$NON-NLS-1$ //$NON-NLS-2$
					rolesPorDefecto;
			// System.out.println (ss);
			stmt2.execute(ss);
			/* } */

			// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si
			// el usuario está activo??)
			if (true /* cacActivo */) { // Lo activamos por defecto (para que no
										// haya que propagar todos los usuarios)
				String[] grupsAndRolesCAC = concatUserGroupsAndRoles(groups,
						roles);
				HashSet grupsAndRolesHash = (grupsAndRolesCAC != null && grupsAndRolesCAC.length != 0) ? new HashSet(
						Arrays.asList(grupsAndRolesCAC)) // eliminem repetits
						: new HashSet(); // evitem error al ésser llista buida
				grupsAndRolesCAC = (String[]) grupsAndRolesHash
						.toArray(new String[0]);
				// 1) Obtenemos los roles que ya tiene
				stmt = sqlConnection
						.prepareStatement("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?"); //$NON-NLS-1$
				stmt.setString(1, user.toUpperCase());
				rset = stmt.executeQuery();
				stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //$NON-NLS-1$
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
					if (/* !active || */!found) {
						stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
								+ user.toUpperCase()
								+ "' AND SOR_GRANTED_ROLE ='" //$NON-NLS-1$
								+ role.toUpperCase() + "'"); //$NON-NLS-1$
						stmt2.close();
					}

				}
				rset.close();
				stmt.close();
				// Añadir los roles que no tiene
				if (/* active && */grupsAndRolesCAC != null)
					for (i = 0; i < grupsAndRolesCAC.length; i++) {
						if (grupsAndRolesCAC[i] != null) {
							stmt2 = sqlConnection
									.prepareStatement("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '" //$NON-NLS-1$
											+ user.toUpperCase()
											+ "', '" + grupsAndRolesCAC[i].toUpperCase() + "' FROM DUAL "); //$NON-NLS-1$ //$NON-NLS-2$
							stmt2.execute();
							stmt2.close();
						}
					}

			}// FIN_CAC_ACTIVO

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ProcessingTaskError"), e); //$NON-NLS-1$
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
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	/**
	 * Actualizar la contraseña del usuario. Asigna la contraseña si el usuario
	 * está activo y la contraseña no es temporal. En caso de contraseñas
	 * temporales, asigna un contraseña aleatoria.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @param mustchange
	 *            es una contraseña temporal?
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public void updateUserPassword(String user, Usuari arg1, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			// Comprobar si el usuario existe
			Connection sqlConnection = getConnection();
			stmt = sqlConnection
					.prepareStatement("SELECT USERNAME FROM SYS.DBA_USERS " + //$NON-NLS-1$
							"WHERE USERNAME='" + user.toUpperCase() + "'"); //$NON-NLS-1$ //$NON-NLS-2$
			ResultSet rset = stmt.executeQuery();
			if (rset.next() && password.getPassword().length() > 0) {
				stmt.close();
				cmd = "ALTER USER \"" + user.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						password.getPassword() + "\""; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
			}
		} catch (SQLException e) {
			handleSQLException(e);
		}/*
		 * catch (UnknownUserException e) { if (stmt!=null) try {stmt.close();}
		 * catch (Exception e2) {} }
		 */catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("OracleAgent.UpdatingPasswordError"), e); //$NON-NLS-1$
		} finally {
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e) {
				}
		}
	}

	/**
	 * Validar contraseña.
	 * 
	 * @param user
	 *            código de usuario
	 * @param password
	 *            contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException
	 *             error de comunicaciones con el servidor
	 * @throws InternalErrorException
	 *             cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups
	 *            vector de grupos
	 * @param roles
	 *            vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public String[] concatUserGroupsAndRoles(Collection<Grup> groups,
			Collection<RolGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getDispatcher().getBasRol()) // roles.length == 0
															// && getRoleBased
															// ()
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Grup g : groups)
				concat.add(g.getCodi());
		}
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	public String[] concatRoleNames(Collection<RolGrant> roles) {
		if (roles.isEmpty() && getDispatcher().getBasRol())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RolGrant rg : roles) {
			concat.add(rg.getRolName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Rol ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		String bd = ri.getBaseDeDades();
		String role = ri.getNom();
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			if (this.getDispatcher().getCodi().equals(bd)) {
				// Comprobar si el rol existe en la bd
				Connection sqlConnection = getConnection();
				stmt = sqlConnection
						.prepareStatement("SELECT ROLE FROM SYS.DBA_ROLES " + //$NON-NLS-1$
								"WHERE ROLE='" + role.toUpperCase() + "'"); //$NON-NLS-1$ //$NON-NLS-2$
				ResultSet rset = stmt.executeQuery();
				if (!rset.next()) // aquest rol NO existeix com a rol de la BBDD
				{
					if (ri != null) {// si el rol encara existeix al seycon (no
										// s'ha esborrat)
						stmt.close();
						cmd = "CREATE ROLE \"" + role.toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$

						if (ri.getContrasenya()) {
							cmd = cmd
									+ " IDENTIFIED BY \"" + rolePassword.getPassword() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						}
						stmt = sqlConnection.prepareStatement(cmd);
						stmt.execute();
						// Fem un revoke per a l'usuari SYSTEM (CAI-579530:
						// u88683)
						stmt.close();
						stmt = sqlConnection
								.prepareStatement("REVOKE \"" + role.toUpperCase() + "\" FROM \"" + user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
						stmt.execute();

						// Aqui en no en tenim encara informació a la bbdd
						// sobre qui té atorgat aquest rol.. no posem res a
						// sc_or_role
					}
				} else // ja existeix a la bbdd
				{
					if (ri != null) {
						// Afegim informació dels usuaris que actualment tenen
						// atorgat el rol a la bbdd (la info no és completa
						// però és consistent amb el rol de bbdd)
						// Ara inserim en SC_OR_ORACLE els usuaris q tinguen el
						// rol a la base de dades
						String cmdrole = "INSERT INTO SC_OR_ROLE(SOR_GRANTEE, SOR_GRANTED_ROLE) " //$NON-NLS-1$
								+ "SELECT GRANTEE, GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTED_ROLE= '" + role.toUpperCase() + "' MINUS " //$NON-NLS-1$ //$NON-NLS-2$
								+ "SELECT SOR_GRANTEE, sor_granted_role FROM SC_OR_ROLE WHERE sor_granted_role='" + role.toUpperCase() + "'"; //$NON-NLS-1$ //$NON-NLS-2$
						stmt = sqlConnection.prepareStatement(cmdrole);
						stmt.execute();
						stmt.close();
					}
				}
				stmt.close();
				rset.close();
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			if (stmt != null)
				try {
					stmt.close();
				} catch (Exception e2) {
				}
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingRole"), e); //$NON-NLS-1$
		}
	}

	private void setAccessControlActive(boolean active)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();
			// Activamos los triggers de logon y de loggoff
			String estado = active ? "ENABLE" : "DISABLE"; //$NON-NLS-1$ //$NON-NLS-2$
			log.info("Activated access control " + active, null, null); //$NON-NLS-1$

			// LOGON
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGON_AUDIT_TRIGGER'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGON_AUDIT_TRIGGER " + estado; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info(
						"Establish 'LOGON_AUDIT_TRIGGER' as " + estado, null, null); //$NON-NLS-1$
			} else {
				log.warn("The trigger 'LOGON_AUDIT_TRIGGER' does not exists"); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_triggers where upper(TRIGGER_NAME) ='LOGOFF_AUDIT_TRIGGER'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				String cmd = "alter trigger LOGOFF_AUDIT_TRIGGER " + estado; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
				stmt.close();
				log.info(
						"Establish 'LOGOFF_AUDIT_TRIGGER' as" + estado, null, null); //$NON-NLS-1$
			} else {
				log.warn("The trigger 'LOGOFF_AUDIT_TRIGGER' does not exists"); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.281"), e); //$NON-NLS-1$
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
	 * 
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
		if (!s_cac_id.equals(cac.getId()))
			return false; // idControlAcces canviat per getId

		// usuari o rol ha de ser nulo (uno de los dos)
		if (s_user == null) {
			if (cac.getUsuariGeneric() != null)
				return false;
		} else {
			if (!s_user.equals(cac.getUsuariGeneric()))
				return false;
		}
		if (s_role == null) {
			if (cac.getDescripcioRol() != null)
				return false;
		} else {
			if (!s_role.equals(cac.getDescripcioRol()))
				return false;
		}
		if (s_host == null) {
			if (cac.getIdMaquina() != null)
				return false;
		} else {
			if (!s_host.equals(cac.getIdMaquina()))
				return false;
		}
		if (s_program == null) {
			if (cac.getProgram() != null)
				return false;
		} else {
			if (!s_program.equals(cac.getProgram()))
				return false;
		}

		return true; // Ha pasat totes les comprovacions

	}

	public void updateAccessControl() throws RemoteException,
			InternalErrorException {
		DispatcherAccessControl dispatcherInfo = null; // Afegit AccessControl
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		try {
			dispatcherInfo = getServer().getDispatcherAccessControl(
					this.getDispatcher().getId());
			// dispatcherInfo =
			// getServer().getDispatcherInfo(this.getDispatcher().getCodi());
			Connection sqlConnection = getConnection();

			if (dispatcherInfo == null) {
				setAccessControlActive(false); // desactivamos triggers
				throw new Exception(Messages.getString("OracleAgent.282") //$NON-NLS-1$
						+ this.getDispatcher().getCodi()
						+ Messages.getString("OracleAgent.283")); //$NON-NLS-1$
			}

			if (dispatcherInfo.getControlAccessActiu()) { // getControlAccessActiu()
				// Lo activamos al final (!!)

				// Obtenemos las reglas de control de acceso
				List<ControlAcces> controlAcces = dispatcherInfo.getControlAcces();
				// ArrayList<ControlAccess> controlAccess =
				// dispatcherInfo.getControlAcces();

				if (controlAcces == null || controlAcces.size() == 0) {
					// Eliminem les regles de control d'accés
					String cmd = "DELETE FROM SC_OR_CONACC"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute(cmd);
					stmt.close();
				} else {
					stmt = sqlConnection
							.prepareStatement("SELECT SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM, SOC_CAC_ID from SC_OR_CONACC"); //$NON-NLS-1$
					rset = stmt.executeQuery();

					while (rset.next()) {
						boolean found = false;
						String s_user = rset.getString(1);
						String s_role = rset.getString(2);
						String s_host = rset.getString(3);
						String s_program = rset.getString(4);
						String s_idcac = rset.getString(5); // por id
															// ¿necesario?

						for (int i = 0; /* !found && */i < controlAcces.size(); i++) {
							ControlAcces cac = controlAcces.get(i);
							if (cac != null
									&& equalsControlAccess(cac, s_user, s_role,
											s_host, s_program, s_idcac)) {
								found = true; // ya existe: no lo creamos
								controlAcces.set(i, null);
							}
						}

						if (!found) {// No l'hem trobat: l'esborrem
							String condicions = ""; //$NON-NLS-1$
							// SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM
							if (s_user == null)
								condicions += " AND SOC_USER is null "; //$NON-NLS-1$
							else
								condicions += " AND SOC_USER=? "; //$NON-NLS-1$
							if (s_role == null)
								condicions += " AND SOC_ROLE is null "; //$NON-NLS-1$
							else
								condicions += " AND SOC_ROLE=? "; //$NON-NLS-1$
							stmt2 = sqlConnection
									.prepareStatement("DELETE SC_OR_CONACC WHERE SOC_HOST=? AND SOC_PROGRAM=? " //$NON-NLS-1$
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
									.prepareStatement("INSERT INTO SC_OR_CONACC(SOC_USER, SOC_ROLE, SOC_HOST, SOC_PROGRAM, SOC_CAC_ID, SOC_HOSTNAME) VALUES (?,?,?,?,?,?)"); //$NON-NLS-1$
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

			} else { // Desactivamos los triggers
				setAccessControlActive(false);
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.293"), e); //$NON-NLS-1$
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

	public Collection<LogEntry> getLogFromDate(Date From)
			throws RemoteException, InternalErrorException {

		PreparedStatement stmt = null;
		ResultSet rset = null;
		// ArrayList<LogEntry> logs = new ArrayList<LogEntry>();
		Collection<LogEntry> logs = null;
		try {
			Connection sqlConnection = getConnection();
			// Obtenemos los logs
			String consulta = "select SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, " //$NON-NLS-1$
					+ "SAC_LOGON_DAY, SAC_OS_USER, SAC_PROGRAM from SC_OR_ACCLOG "; //$NON-NLS-1$

			if (From != null)
				consulta += "WHERE SAC_LOGON_DAY>=? "; //$NON-NLS-1$
			consulta += " order by SAC_LOGON_DAY "; //$NON-NLS-1$
			log.info("consulta: "+consulta);
			stmt = sqlConnection.prepareStatement(consulta);

			if (From != null)
				stmt.setTimestamp(1, new java.sql.Timestamp(From.getTime()));
			rset = stmt.executeQuery();
			String cadenaConnexio = db;
			int posArroba = cadenaConnexio.indexOf("@"); //$NON-NLS-1$
			int posDosPunts = cadenaConnexio.indexOf(":", posArroba); //$NON-NLS-1$
			String hostDB = null;
			if (posArroba != -1 && posDosPunts != -1)
				hostDB = cadenaConnexio.substring(posArroba + 1, posDosPunts); // nombre
																				// del
																				// servidor
			if (hostDB == null || "localhost".equalsIgnoreCase(hostDB)) //$NON-NLS-1$
				hostDB = InetAddress.getLocalHost().getCanonicalHostName();
			while (rset.next() && logs.size() <= 100) { // Limitem per 100 file
				LogEntry log = new LogEntry();
				log.setHost(hostDB);
				log.setProtocol("OTHER"); // De la tabla de serveis //$NON-NLS-1$

				// Usuario S.O.
				log.setUser(rset.getString(6));
				log.SessionId = rset.getString(2);
				log.info = "dbUser: " + rset.getString(1) + " Program: " + rset.getString(7); //7 = program //$NON-NLS-1$ //$NON-NLS-2$
				String proceso = rset.getString(3);
				if ("logon".equalsIgnoreCase(proceso)) //$NON-NLS-1$
					log.type = LogEntry.LOGON;
				else if ("logoff".equalsIgnoreCase(proceso)) //$NON-NLS-1$
					log.type = LogEntry.LOGOFF;
				else if ("not-allowed".equalsIgnoreCase(proceso)) { //$NON-NLS-1$
					log.type = LogEntry.LOGON_DENIED;
					log.info += " LOGON DENIED (Access control)"; //$NON-NLS-1$
				} else
					log.type = -1; // desconocido
				log.setClient(rset.getString(4));
				log.setDate(rset.getTimestamp(5));

				logs.add(log);
			}
			rset.close();
			stmt.close();
			return logs; // .toArray(new LogEntry[0]);
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.308"), e); //$NON-NLS-1$
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
		try {
			Connection sqlConnection = getConnection();
			if (this.getDispatcher().getCodi().equals(bbdd)) {
				PreparedStatement stmtCAC = null;
				stmtCAC = sqlConnection
						.prepareStatement("DROP ROLE \"" + nom.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$
				stmtCAC.execute();
				stmtCAC.close();
				// Borramos las filas de control de acceso relacionadas
				// con el ROL

				ResultSet rsetCAC = null;
				try {
					stmtCAC = sqlConnection
							.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'"); //$NON-NLS-1$
					rsetCAC = stmtCAC.executeQuery();

					if (rsetCAC.next()) { // Borramos referencias al rol en la
											// tabla SC_OR_ROLE
						stmtCAC.close();
						stmtCAC = sqlConnection
								.prepareStatement("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTED_ROLE='" + nom.toUpperCase() + "'"); //$NON-NLS-1$ //$NON-NLS-2$
						stmtCAC.execute();
						stmtCAC.close();
					}
				} finally {
					try {
						rsetCAC.close();
					} catch (Exception ex) {
					}
					try {
						stmtCAC.close();
					} catch (Exception ex) {
					}
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void removeUser(String arg0) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		try {
			Connection sqlConnection = getConnection();
			PreparedStatement stmt = null;
			stmt = sqlConnection
					.prepareStatement("REVOKE CREATE SESSION FROM \"" + arg0.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$
			try {
				stmt.execute();
			} catch (SQLException e) {
			} finally {
				stmt.close();
			}
			// Borramos las referencias de la tabla de control de acceso
			if (true/* cacActivo */) { // Lo activamos por defecto
				stmt = sqlConnection
						.prepareStatement("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
								+ arg0.toUpperCase() + "'"); //$NON-NLS-1$
				try {
					stmt.execute();
				} catch (SQLException e) {
				} finally {
					stmt.close();
				}
			}
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.318"), e); //$NON-NLS-1$
		}
	}

	public void updateUser(String nom, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
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
			roles = getServer().getAccountRoles(nom,
					this.getDispatcher().getCodi());

			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			stmtCAC = sqlConnection
					.prepareStatement("select 1 from user_tables where table_name ='SC_OR_ROLE'"); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (rsetCAC.next()) {
				cacActivo = true; // la tabla existe (no miramos si está activo
									// o no, nos da igual)
			}
			rsetCAC.close();
			stmtCAC.close();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement("SELECT 1 FROM SYS.DBA_USERS WHERE USERNAME=?"); //$NON-NLS-1$
			stmt.setString(1, nom.toUpperCase());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (!rset.next()) {
				stmt.close();

				Password pass = getServer().getOrGenerateUserPassword(nom,
						getDispatcher().getCodi());

				String cmd = "CREATE USER \"" + nom.toUpperCase() + "\" IDENTIFIED BY \"" + //$NON-NLS-1$ //$NON-NLS-2$
						pass.getPassword() + "\" TEMPORARY TABLESPACE TEMP " + //$NON-NLS-1$
						"DEFAULT TABLESPACE USERS "; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
			}

			rset.close();
			stmt.close();
			// Dar o revocar permiso de create session : La part de revocar
			// passada a removeUser()
			stmt = sqlConnection
					.prepareStatement("GRANT CREATE SESSION TO  \"" + nom.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.execute();
			stmt.close();

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?"); //$NON-NLS-1$
			stmt.setString(1, nom.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //no s'admet constructor buit //$NON-NLS-1$
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);

				for (RolGrant ro : roles) {
					if (ro != null && ro.getRolName().equalsIgnoreCase(role)) {
						found = true;
						ro = null;
					}
				}
				if (!found)
					stmt2.execute("REVOKE \"" + role + "\" FROM \"" + nom.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RolGrant r : roles) {
				if (r != null) {
					if (rolesPorDefecto == null)
						rolesPorDefecto = "\"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					else
						rolesPorDefecto = rolesPorDefecto
								+ ",\"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
					stmt = sqlConnection
							.prepareStatement("SELECT 1 FROM SYS.DBA_ROLES WHERE ROLE=?"); //$NON-NLS-1$
					stmt.setString(1, r.getRolName().toUpperCase());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						// Password protected or not
						String command = "CREATE ROLE \"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						if (getServer().getRoleInfo(r.getRolName(),
								r.getDispatcher()).getContrasenya())
							command = command
									+ " IDENTIFIED BY \"" + rolePassword.getPassword() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						stmt2.execute(command);
						// Revoke de mi mismo
						stmt2.execute("REVOKE \"" + r.getRolName().toUpperCase() + "\" FROM \"" + this.user.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
					} else {
						String command = "ALTER ROLE \"" + r.getRolName().toUpperCase() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						if (getServer().getRoleInfo(r.getRolName(),
								r.getDispatcher()).getContrasenya())
							command = command
									+ " IDENTIFIED BY \"" + rolePassword.getPassword() + "\""; //$NON-NLS-1$ //$NON-NLS-2$
						else
							command = command + " NOT IDENTIFIED"; //$NON-NLS-1$
						stmt2.execute(command);
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (RolGrant ros : roles) {
				if (ros != null) {
					stmt2.execute("GRANT \"" + ros.getRolName().toUpperCase() + "\" TO  \"" + nom.toUpperCase() + "\""); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				}
			}

			// Ajustar los roles por defecto
			if (rolesPorDefecto == null)
				rolesPorDefecto = "NONE"; //$NON-NLS-1$
			String ss = "ALTER USER \"" + nom.toUpperCase() + "\" DEFAULT ROLE " + rolesPorDefecto; //$NON-NLS-1$ //$NON-NLS-2$
			stmt2.execute(ss);

			// Insertamos en la tabla de roles para CONTROL DE ACCESO (¿solo si
			// el usuario está activo??)
			String[] rolesCAC = concatRoleNames(roles);
			HashSet grupsAndRolesHash = (rolesCAC != null && rolesCAC.length != 0) ? new HashSet(
					Arrays.asList(rolesCAC)) // eliminem repetits
					: new HashSet(); // evitem error al ésser llista buida
			rolesCAC = (String[]) grupsAndRolesHash.toArray(new String[0]);
			// 1) Obtenemos los roles que ya tiene
			stmt = sqlConnection
					.prepareStatement("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?"); //$NON-NLS-1$
			stmt.setString(1, nom.toUpperCase());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.prepareStatement("select 1 from dual"); //$NON-NLS-1$
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; rolesCAC != null && !found && i < rolesCAC.length; i++) {
					if (rolesCAC[i] != null
							&& rolesCAC[i].equalsIgnoreCase(role)) {
						found = true;
						rolesCAC[i] = null;
					}
				}
				if (!found) {
					stmt2.execute("DELETE FROM SC_OR_ROLE WHERE SOR_GRANTEE='" //$NON-NLS-1$
							+ nom.toUpperCase() + "' AND SOR_GRANTED_ROLE ='" //$NON-NLS-1$
							+ role.toUpperCase() + "'"); //$NON-NLS-1$
					stmt2.close();
				}
			}
			rset.close();
			stmt.close();
			// Añadir los roles que no tiene
			if (rolesCAC != null)
				for (i = 0; i < rolesCAC.length; i++) {
					if (rolesCAC[i] != null) {
						stmt2 = sqlConnection
								.prepareStatement("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) SELECT '" //$NON-NLS-1$
										+ nom.toUpperCase()
										+ "', '" + rolesCAC[i].toUpperCase() + "' FROM DUAL "); //$NON-NLS-1$ //$NON-NLS-2$
						stmt2.execute();
						stmt2.close();
					}
				}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
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
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT USERNAME FROM SYS.DBA_USERS"); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				accounts.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return accounts;
	}

	public Account getAccountInfo(String userAccount) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT ACCOUNT_STATUS FROM SYS.DBA_USERS WHERE USERNAME=?"); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Account account = new Account ();
				account.setName(userAccount);
				account.setName(userAccount);
				account.setDispatcher(getCodi());
				account.setDisabled( ! "OPEN".equals(rset.getString(1)));
				return account;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<String> getRolesList() throws RemoteException,
			InternalErrorException {
		LinkedList<String> roles = new LinkedList<String>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT ROLE FROM SYS.DBA_ROLES"); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				roles.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
		return roles;
	}

	public Rol getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT ROLE FROM SYS.DBA_ROLES WHERE ROLE=?"); //$NON-NLS-1$
			stmt.setString(1, roleName);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Rol r = new Rol();
				r.setBaseDeDades(getCodi());
				r.setNom(rset.getString(1));
				r.setDescripcio(rset.getString(1));
				return r;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
			if (stmt2 != null)
				try {
					stmt2.close();
				} catch (Exception e) {
				}
		}
		return null;
	}

	public List<RolGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		LinkedList<RolGrant> roles = new LinkedList<RolGrant>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT GRANTED_ROLE FROM SYS.DBA_ROLE_PRIVS WHERE GRANTEE=?"); //$NON-NLS-1$
			stmt.setString(1,  userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				RolGrant rg = new RolGrant();
				rg.setDispatcher(getCodi());
				rg.setRolName(rset.getString(1));
				rg.setOwnerAccountName(userAccount);
				rg.setOwnerDispatcher(getCodi());
				roles.add(rg);
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
		return roles;
	}
}