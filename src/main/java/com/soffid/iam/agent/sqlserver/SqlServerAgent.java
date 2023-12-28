package com.soffid.iam.agent.sqlserver;

import java.net.InetAddress;
import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.AccessControl;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.System;
import com.soffid.iam.api.SystemAccessControl;
import com.soffid.iam.api.User;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.intf.AccessControlMgr;
import com.soffid.iam.sync.intf.AccessLogMgr;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;

import es.caib.seycon.ng.exception.InternalErrorException;
import es.caib.seycon.ng.sync.intf.LogEntry;

/**
 * Agente SEYCON para gestionar bases de datos SQL Server
 * <P>
 */

public class SqlServerAgent extends Agent implements UserMgr, RoleMgr, ReconcileMgr2, AccessLogMgr, AccessControlMgr {
	/** Usuario SQL Server */
	transient String user;
	/** Contraseña SQL Server */
	transient Password password;
	/** Cadena de conexión a la base de datos */
	transient String db;
	/** Valor que activa o desactiva el debug */
	transient boolean debug;
	private boolean actualitzaTriggers;
	/**
	 * Hash de conexiones ya establecidas. De esta forma se evita que el agente
	 * seycon abra conexiones sin control debido a problemas de comunicaciones con
	 * el servidor
	 */
	static Hashtable hash = new Hashtable();

	/* versió dels triggers del control d'accés */
	private final static String VERSIO = "1.2"; //$NON-NLS-1$

	/**
	 * Constructor
	 * 
	 * @param params vector con parámetros de configuración:
	 *               <LI>0 = usuario</LI>
	 *               <LI>1 = contraseña</LI>
	 *               <LI>2 = cadena de conexión a la base de datos</LI>
	 *               <LI>3 = contraseña con la que se protegerán los roles</LI>
	 */
	public SqlServerAgent() throws java.rmi.RemoteException {
		super();
	}

	/**
	 * Inicializar el agente.
	 */
	public void init() throws InternalErrorException {
		log.info("Starting SQL Server agent {}", getSystem().getName(), null); //$NON-NLS-1$
		user = getSystem().getParam0();
		password = Password.decode(getSystem().getParam1());
		db = getSystem().getParam2();
		debug = "true".equals(getSystem().getParam4());

		boolean createChild = "true".equals(getSystem().getParam3());
		debug = "true".equals(getSystem().getParam4());
		if (debug) {
			log.info("user: " + user);
			log.info("password: ********");
			log.info("db: " + db);
			log.info("createChild: " + createChild);
			log.info("debug: " + debug);
		}

		String instance = null;
		int i = db.toLowerCase().indexOf(";databasename=");
		if (i >= 0) {
			int j = db.indexOf(";", i + 1);
			if (j < 0)
				instance = db.substring(i + 14);
			else
				instance = db.substring(i + 14, j);
		}
		if (instance == null) {
			instance = "master";
			db = db + ";databaseName=master";
		}

		if (debug)
			log.info("Database instance = " + instance);
		// Verifiramos que estén creadas las tablas y los triggers
		if (createChild && instance.equalsIgnoreCase("master")) {
			if (debug)
				log.info("Creating child dispatchers");
			createChildDispatchers();
		}
	}

	private void createChildDispatchers() throws InternalErrorException {
		PreparedStatement stmt = null;
		ResultSet rset = null;

		DispatcherService svc = ServiceLocator.instance().getDispatcherService();
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection.prepareStatement("SELECT name from sys.databases"); //$NON-NLS-1$
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				String name = rset.getString(1);
				if (!name.equals("master")) {
					System d = svc.findDispatcherByName(getAgentName() + "/" + name);
					if (d == null) {
						d = new System(getSystem());
						d.setId(null);
						d.setName(d.getName() + "/" + name);

						String db = getSystem().getParam2();
						int i = db.indexOf(";databaseName=");
						if (i >= 0) {
							int j = db.indexOf(";", i + 1);
							if (j < 0)
								db = db.substring(0, i);
							else
								db = db.substring(0, i) + db.substring(j);
						}
						db = db + ";databaseName=" + name;
						d.setParam2(db);
						d.setParam3("false");
						svc.create(d);
					}
				}
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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
	}

	/**
	 * Liberar conexión a la base de datos. Busca en el hash de conexiones activas
	 * alguna con el mismo nombre que el agente y la libera. A continuación la
	 * elimina del hash. Se invoca desde el método de gestión de errores SQL.
	 */
	public void releaseConnection() {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn != null) {
			hash.remove(this.getSystem().getName());
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
	 * conexión con la base de datos y la registra en el hash de conexiones activas
	 * 
	 * @return conexión SQL asociada.
	 * @throws InternalErrorException algún error en el proceso de conexión
	 */
	public Connection getConnection() throws InternalErrorException {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn == null) {
			try {
				DriverManager.registerDriver(new com.microsoft.sqlserver.jdbc.SQLServerDriver());
				// Connect to the database
				conn = DriverManager.getConnection(db, user, password.getPassword());
				hash.put(this.getSystem().getName(), conn);
			} catch (SQLException e) {
				e.printStackTrace();
				throw new InternalErrorException(Messages.getString("OracleAgent.ConnectionError"), e); //$NON-NLS-1$
			}
		}
		return conn;
	}

	/**
	 * Gestionar errores SQL. Debe incovarse cuando se produce un error SQL. Si el
	 * sistema lo considera oportuno cerrará la conexión SQL.
	 * 
	 * @param e Excepción oralce producida
	 * @throws InternalErrorExcepción error que se debe propagar al servidor (si es
	 *                                neceasario)
	 */
	public void handleSQLException(SQLException e) throws InternalErrorException {
		if (debug)
			log.warn(this.getSystem().getName() + " SQL Exception: ", e); //$NON-NLS-1$
		releaseConnection();
		throw new InternalErrorException("Error executing statement", e);
	}

	public void updateUser(Account account)
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		// boolean active;
		PreparedStatement stmt = null;
		Statement stmt2 = null;
		ResultSet rset = null;
		// String groupsConcat = "";
		Collection<RoleGrant> roles;
		Collection<Group> groups;

		String groupsAndRoles[];
		int i;

		try {
			// Obtener los datos del usuario
			roles = getServer().getAccountRoles(account.getName(), account.getSystem());

			groups = null;
			groupsAndRoles = concatUserGroupsAndRoles(groups, roles);

			Connection sqlConnection = getConnection();

			if (debug)
				log.info("Checking login " + account.getName());
			// Comprobar si el usuario existe
			stmt = sqlConnection.prepareStatement("SELECT name FROM sys.syslogins WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (!rset.next()) {
				if (debug)
					log.info("Account " + account.getName() + " not found");
				if (account.getStatus() != AccountStatus.REMOVED) {
					stmt.close();

					Password pass = getServer().getOrGenerateUserPassword(account.getName(), getSystem().getName());

					String cmd;
					if (!account.getName().contains("\\")) {
						if (debug)
							log.info("Creating login " + account.getName() + " from locally");
						Password p = getServer().getOrGenerateUserPassword(account.getName(), account.getSystem());
						if (p == null)
							cmd = "CREATE LOGIN [" + account.getName() + "]"; //$NON-NLS-1$
						else
							cmd = "CREATE LOGIN [" + account.getName() + "] WITH PASSWORD = '" //$NON-NLS-1$
									+ p.getPassword().replaceAll("'", "''") + "'";
					} else {
						if (debug)
							log.info("Creating login " + account.getName() + " from windows");
						cmd = "CREATE LOGIN [" + account.getName() + "] FROM WINDOWS"; //$NON-NLS-1$
					}
					if (debug)
						log.info(cmd);
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute();
				}
			}
			rset.close();
			stmt.close();

			// Comprobar si el usuario existe
			stmt = sqlConnection.prepareStatement("SELECT name FROM sys.sysusers WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (debug)
				log.info("Checking user " + account.getName() + "");
			if (!rset.next()) {
				if (!account.isDisabled()) {
					if (debug)
						log.info("Creating user " + account.getName() + "");
					stmt.close();

					String cmd;
					cmd = "CREATE USER [" + account.getName() + "]"; //$NON-NLS-1$
					if (debug)
						log.info(cmd);
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute();
				}
			} else {
				log.info("Found user " + rset.getString(1));
				if (account.getStatus() == AccountStatus.REMOVED) {
					if (debug)
						log.info("DROP USER [" + account.getName() + "]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("DROP USER [" + account.getName() + "]");
					stmt2.close();
				} else if (account.isDisabled()) {
					if (debug)
						log.info("REVOKE CONNECT FROM [" + account.getName() + "]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("REVOKE CONNECT FROM [" + account.getName() + "]");
					stmt2.close();
				} else {
					if (debug)
						log.info("GRANT CONNECT TO [" + account.getName() + "]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("GRANT CONNECT TO [" + account.getName() + "]");
					stmt2.close();
				}

			}
			if (account.getStatus() == AccountStatus.REMOVED || account.isDisabled())
				return;

			// System.out.println ("Usuario "+user+" ya existe");
			rset.close();
			stmt.close();

			if (debug)
				log.info("Checking grants " + account.getName() + " ");

			// Eliminar los roles que sobran
			stmt = sqlConnection.prepareStatement("SELECT DP1.name AS DatabaseRoleName,   \n"
					+ "   isnull (DP2.name, 'No members') AS DatabaseUserName   \n"
					+ " FROM sys.database_role_members AS DRM  \n" + " JOIN sys.database_principals AS DP1  \n"
					+ "   ON DRM.role_principal_id = DP1.principal_id  \n" + " JOIN sys.database_principals AS DP2  \n"
					+ "   ON DRM.member_principal_id = DP2.principal_id  \n" + "WHERE DP1.type = 'R' AND DP2.name=?\n"
					+ "ORDER BY DP1.name;  "); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.createStatement();
			while (rset.next()) {
				boolean found = false;
				String role = rset.getString(1);
				for (i = 0; groupsAndRoles != null && !found && i < groupsAndRoles.length; i++) {
					if (groupsAndRoles[i] != null && groupsAndRoles[i].equalsIgnoreCase(role)) {
						found = true;
						groupsAndRoles[i] = null;
					}
				}
				if (!found)
					stmt2.execute("EXEC sp_droprolemember [" + role + "], [" + account.getName() + "];"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
			}
			rset.close();
			stmt.close();

			String rolesPorDefecto = null;

			// Crear los roles si son necesarios
			for (RoleGrant r : roles) {
				if (r != null) {
					stmt = sqlConnection
							.prepareStatement("SELECT name from sys.database_principals WHERE type = 'R' AND name=?"); //$NON-NLS-1$
					stmt.setString(1, r.getRoleName());
					rset = stmt.executeQuery();
					if (!rset.next()) {
						// Password protected or not
						String command = "CREATE ROLE [" + r.getRoleName() + "]"; //$NON-NLS-1$ //$NON-NLS-2$
						stmt2.execute(command);
						// Revoke de mi mismo
					}
					rset.close();
					stmt.close();
				}
			}

			// Añadir los roles que no tiene
			for (i = 0; /* active && */groupsAndRoles != null && i < groupsAndRoles.length; i++) {
				if (groupsAndRoles[i] != null) {
					stmt2.execute("EXEC sp_addrolemember [" + groupsAndRoles[i] + "], [" + account.getName() + "];"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				}
			}
			if (Boolean.TRUE.equals( getSystem().getAccessControl()))
			{
				updateAccessManagementRoles(sqlConnection, account.getName(), roles);
			}// FIN_CAC_ACTIVO
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.ProcessingTaskError"), e); //$NON-NLS-1$
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

	private void updateAccessManagementRoles(Connection sqlConnection, String user, Collection<RoleGrant> roles) throws SQLException {
		String[] grupsAndRolesCAC = concatUserGroupsAndRoles(null, roles);
		PreparedStatement stmt = sqlConnection
				.prepareStatement(sentence("SELECT SOR_GRANTED_ROLE FROM SC_OR_ROLE WHERE SOR_GRANTEE=?")); //$NON-NLS-1$
		stmt.setString(1, user.toUpperCase());
		ResultSet rset = stmt.executeQuery();
		Statement stmt2 = sqlConnection.createStatement(); //$NON-NLS-1$
		while (rset.next()) {
			boolean found = false;
			String role = rset.getString(1);
			for (int i = 0; grupsAndRolesCAC != null && !found
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
			for (int i = 0; i < grupsAndRolesCAC.length; i++) {
				if (grupsAndRolesCAC[i] != null) {
					PreparedStatement pstmt = sqlConnection
							.prepareStatement(sentence("INSERT INTO SC_OR_ROLE (SOR_GRANTEE, SOR_GRANTED_ROLE) VALUES (?, ?)")); //$NON-NLS-1$
					pstmt.setString(1,  user.toUpperCase());
					pstmt.setString(2,  grupsAndRolesCAC[i].toUpperCase());
					pstmt.execute();
					pstmt.close();
				}
			}

	}

	public void updateUserPassword(String user, User arg1, Password password, boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		updateUserPassword(user, password);

	}

	public void updateUserPassword(String user, Password password) throws InternalErrorException {
		if (user.contains("\\"))
			return;
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			// Comprobar si el usuario existe
			Connection sqlConnection = getConnection();
			stmt = sqlConnection.prepareStatement("SELECT name from sys.syslogins " + //$NON-NLS-1$
					"WHERE name=?"); //$NON-NLS-1$ //$NON-NLS-2$
			stmt.setString(1, user);
			ResultSet rset = stmt.executeQuery();
			if (rset.next() && password.getPassword().length() > 0) {
				stmt.close();
				cmd = "ALTER LOGIN [" + user + "] with password = '" + //$NON-NLS-1$ //$NON-NLS-2$
						password.getPassword().replaceAll("'", "''") + "'"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(cmd);
				stmt.execute();
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
			throw new InternalErrorException(Messages.getString("OracleAgent.UpdatingPasswordError"), e); //$NON-NLS-1$
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
	 * @param user     código de usuario
	 * @param password contraseña a asignar
	 * @return false
	 * @throws java.rmi.RemoteException error de comunicaciones con el servidor
	 * @throws InternalErrorException   cualquier otro problema
	 */
	public boolean validateUserPassword(String user, Password password)
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		return false;
	}

	/**
	 * Concatenar los vectores de grupos y roles en uno solo. Si el agente está
	 * basado en roles y no tiene ninguno, retorna el valor null
	 * 
	 * @param groups vector de grupos
	 * @param roles  vector de roles
	 * @return vector con nombres de grupo y role
	 */
	public String[] concatUserGroupsAndRoles(Collection<Group> groups, Collection<RoleGrant> roles) {
		int i;
		int j;

		if (roles.isEmpty() && getSystem().getRolebased().booleanValue())
			return null;
		LinkedList<String> concat = new LinkedList<String>();
		if (groups != null) {
			for (Group g : groups)
				concat.add(g.getName());
		}
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	public String[] concatRoleNames(Collection<RoleGrant> roles) {
		if (roles.isEmpty() && getSystem().getRolebased())
			return null;

		LinkedList<String> concat = new LinkedList<String>();
		for (RoleGrant rg : roles) {
			concat.add(rg.getRoleName());
		}

		return concat.toArray(new String[concat.size()]);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String, java.lang.String)
	 */
	public void updateRole(Role ri) throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		String bd = ri.getSystem();
		String role = ri.getName();
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			if (this.getSystem().getName().equals(bd)) {
				// Comprobar si el Role existe en la bd
				Connection sqlConnection = getConnection();
				stmt = sqlConnection
						.prepareStatement("SELECT name from sys.database_principals WHERE type = 'R' AND name=?"); //$NON-NLS-1$
				stmt.setString(1, role);
				ResultSet rset = stmt.executeQuery();
				if (!rset.next()) // aquest Role NO existeix com a Role de la BBDD
				{
					if (ri != null) {// si el Role encara existeix al seycon (no
										// s'ha esborrat)
						stmt.close();
						String command = "CREATE ROLE [" + role + "]"; //$NON-NLS-1$ //$NON-NLS-2$
						stmt = sqlConnection.prepareStatement(command);
						stmt.execute();
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
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingRole"), e); //$NON-NLS-1$
		}
	}

	public void removeRole(String nom, String bbdd) {
		try {
			Connection sqlConnection = getConnection();
			if (this.getSystem().getName().equals(bbdd)) {
				PreparedStatement stmt = sqlConnection
						.prepareStatement("SELECT name from sys.database_principals WHERE type = 'R' AND name=?"); //$NON-NLS-1$
				stmt.setString(1, nom);
				ResultSet rset = stmt.executeQuery();
				if (rset.next()) {
					Statement stmt2 = sqlConnection.createStatement();
					stmt2.execute("DROP ROLE [" + nom + "]");
					stmt2.close();
				}
				rset.close();
				stmt.close();
			}
		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public void removeUser(String arg0) throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		Account account = getServer().getAccountInfo(arg0, getAgentName());
		if (account == null) {
			account = new Account();
			account.setName(arg0);
			account.setSystem(getAgentName());
			account.setStatus(AccountStatus.REMOVED);
		}
		updateUser(account);
	}

	public void updateUser(String nom, String descripcio)
			throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(nom, getAgentName());
		if (acc == null) {
			acc = new Account();
			acc.setName(nom);
			acc.setDescription(descripcio);
			acc.setStatus(AccountStatus.REMOVED);
		}
		updateUser(acc);
	}

	public void updateUser(Account account, User user)
			throws RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		updateUser(account);
	}

	public List<String> getAccountsList() throws RemoteException, InternalErrorException {
		LinkedList<String> accounts = new LinkedList<String>();
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		Collection<RoleGrant> roles;

		int i;

		// Control de acceso (tabla de roles)
		boolean cacActivo = false; // indica si está activo el control de acceso
		PreparedStatement stmtCAC = null;
		ResultSet rsetCAC = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection.prepareStatement("SELECT name FROM sys.sysusers"); //$NON-NLS-1$
			rset = stmt.executeQuery();
			while (rset.next()) {
				accounts.add(rset.getString(1));
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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

	public Account getAccountInfo(String userAccount) throws RemoteException, InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection.prepareStatement("SELECT name, hasdbaccess FROM sys.sysusers WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				int access = rset.getInt(2);
				Account account = new Account();
				account.setName(userAccount);
				account.setName(userAccount);
				account.setSystem(getAgentName());
				account.setDisabled(access == 0);
				return account;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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

	public List<String> getRolesList() throws RemoteException, InternalErrorException {
		LinkedList<String> roles = new LinkedList<String>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection.prepareStatement("SELECT name from sys.database_principals where type = 'R'"); //$NON-NLS-1$
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
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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

	public Role getRoleFullInfo(String roleName) throws RemoteException, InternalErrorException {
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		// Control de acceso (tabla de roles)
		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT name from sys.database_principals WHERE type = 'R' AND name=?"); //$NON-NLS-1$
			stmt.setString(1, roleName);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				Role r = new Role();
				r.setSystem(getAgentName());
				r.setName(rset.getString(1));
				r.setDescription(rset.getString(1));
				return r;
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.ErrorUpdatingUser"), e); //$NON-NLS-1$
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

	public List<RoleGrant> getAccountGrants(String userAccount) throws RemoteException, InternalErrorException {
		LinkedList<RoleGrant> roles = new LinkedList<RoleGrant>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection.prepareStatement("SELECT DP1.name AS DatabaseRoleName,   \n"
					+ "   isnull (DP2.name, 'No members') AS DatabaseUserName   \n"
					+ " FROM sys.database_role_members AS DRM  \n" + " JOIN sys.database_principals AS DP1  \n"
					+ "   ON DRM.role_principal_id = DP1.principal_id  \n" + " JOIN sys.database_principals AS DP2  \n"
					+ "   ON DRM.member_principal_id = DP2.principal_id  \n" + "WHERE DP1.type = 'R' AND DP2.name=?\n"
					+ "ORDER BY DP1.name;  "); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			while (rset.next()) {
				RoleGrant rg = new RoleGrant();
				rg.setSystem(getAgentName());
				rg.setRoleName(rset.getString(1));
				rg.setOwnerAccountName(userAccount);
				rg.setOwnerSystem(getAgentName());
				roles.add(rg);
			}

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error updating user", e); //$NON-NLS-1$
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

	private void createAccessControlTables()
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// Comprobamos que exista la tabla de roles de control de acceso
			// SC_OR_ACCLOG: tabla de logs
			stmtCAC = sqlConnection.prepareStatement(
					sentence("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME ='SC_OR_ACCLOG'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				int anyo = Calendar.getInstance().get(Calendar.YEAR);
				// La creamos PARTICIONADA para el año actual
				String cmd = "create table SC_OR_ACCLOG  ( " + //$NON-NLS-1$
						"   sac_user_id		varchar(50)," + // $NON-NLS-1$
						"   sac_session_Id	varchar(50)," + // $NON-NLS-1$
						"   sac_process		varchar(50)," + // $NON-NLS-1$
						"   sac_host		varchar(50)," + // $NON-NLS-1$
						"   sac_logon_day	timestamp," + // $NON-NLS-1$
						"   sac_os_user		varchar(50)," + // $NON-NLS-1$
						"   sac_program		varchar(80)" + // $NON-NLS-1$
						" )"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Created table 'SC_OR_ACCLOG', year {}", anyo, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_CONACC
			stmtCAC = sqlConnection.prepareStatement(
					sentence("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME ='SC_OR_CONACC'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_CONACC  ( " + //$NON-NLS-1$
						"  SOC_USER VARCHAR(50) " + //$NON-NLS-1$
						", SOC_ROLE VARCHAR(50) " + //$NON-NLS-1$
						", SOC_HOST VARCHAR(50)" + //$NON-NLS-1$
						", SOC_PROGRAM VARCHAR(80) " + //$NON-NLS-1$
						", SOC_CAC_ID  BIGINT " + //$NON-NLS-1$
						", SOC_HOSTNAME  VARCHAR(50) " + //$NON-NLS-1$
						")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Created table 'SC_OR_CONACC'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_ROLE
			stmtCAC = sqlConnection.prepareStatement(
					sentence("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME ='SC_OR_ROLE'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_ROLE  ( " //$NON-NLS-1$
						+ "  	SOR_GRANTEE VARCHAR(50) NOT NULL " //$NON-NLS-1$
						+ " 	, SOR_GRANTED_ROLE VARCHAR(50) NOT NULL " //$NON-NLS-1$
						+ ")"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Created table 'SC_OR_ROLE'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// SC_OR_VERSIO
			stmtCAC = sqlConnection.prepareStatement(
					sentence("SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_NAME ='SC_OR_VERSIO'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			if (!rsetCAC.next()) {
				// Creamos la tabla:
				String cmd = "CREATE TABLE SC_OR_VERSIO  ( " //$NON-NLS-1$
						+ "  SOV_VERSIO VARCHAR(20) " //$NON-NLS-1$
						+ ", SOV_DATA DATE)"; //$NON-NLS-1$ //$NON-NLS-2$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Created table 'SC_OR_VERSIO'", null, null); //$NON-NLS-1$
			}
			rsetCAC.close();
			stmtCAC.close();

			// Ací comprovem que la versió dels triggers corresponga amb la
			// versió actual
			actualitzaTriggers = false; // Per defecte NO s'actualitzen
			// obtenim la darrera versió del trigger
			stmtCAC = sqlConnection.prepareStatement(sentence(
					"select SOV_VERSIO from SC_OR_VERSIO where sov_data = (select max(SOV_DATA) from SC_OR_VERSIO)", //$NON-NLS-1$
					null));
			rsetCAC = stmtCAC.executeQuery();

			// Mirem si no existeix cap fila o si la versió és diferent a la
			// actual
			if (!rsetCAC.next()) {
				// No existeix cap, actualitzem i inserim una fila
				actualitzaTriggers = true;
				String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.setString(1, VERSIO);
				stmt.execute();
				stmt.close();
				if (debug)
					log.info("Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
			} else {
				String versioActual = rsetCAC.getString(1);
				if (!VERSIO.equals(versioActual)) {
					// És una versió diferent, l'hem d'actualitzar
					actualitzaTriggers = true;
					// Guardem la versió actual
					String cmd = "insert into SC_OR_VERSIO (SOV_VERSIO) VALUES (?)"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(sentence(cmd, null));
					stmt.setString(1, VERSIO);

					stmt.execute();
					stmt.close();
					if (debug)
						log.info("Detected different agent version, triggers will be updated", null, null); //$NON-NLS-1$
				}
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error registering logon trigger", e); //$NON-NLS-1$
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

	private void createAccessControl()
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			if (actualitzaTriggers) {
				dropAccessControl();
				actualitzaTriggers = false;
			}
			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection.prepareStatement(
					sentence("select 1 from sys.server_triggers where name ='logon_audit_trigger'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogonTrigger = rsetCAC.next();

			if (!existeLogonTrigger ) {

				// Creamos o reemplazamos el TRIGGER:
				String cmd = "create TRIGGER logon_audit_trigger\n" 
						+ "on ALL SERVER WITH EXECUTE AS '" + user + "'\n"
						+ "FOR LOGON\n" 
						+ "AS \n" 
						+ "BEGIN \n" 
						+ "    DECLARE @IP_Address varchar(255);\n" 
						+ "    SELECT @IP_Address = client_net_address\n" 
						+ "    FROM sys.dm_exec_connections\n"
						+ "    WHERE Session_id = @@SPID;\n" 
						+ "    IF (select COUNT(*) FROM SC_OR_CONACC  \n"
						+ "      where ( SOC_USER is null or upper(ORIGINAL_LOGIN()) like upper(SOC_USER)) and \n"
						+ "      	   ( SOC_ROLE is null\n"
						+ "              OR EXISTS (select 1 from SC_OR_ROLE where SOR_GRANTEE=ORIGINAL_LOGIN() and SOR_GRANTED_ROLE = SOC_ROLE)) AND\n"
						+ "		       (@IP_Address like SOC_HOST) AND\n"
						+ "            (UPPER(APP_NAME()) like UPPER(SOC_PROGRAM))) = 0\n"
						+ "		BEGIN\n"
						+ "		    BEGIN TRANSACTION T1 \n"
						+ "	   		insert into SC_OR_ACCLOG (SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, SAC_LOGON_DAY, SAC_PROGRAM)\n"
						+ "		    VALUES (ORIGINAL_LOGIN(),  @@SPID, 'not-allowed',  @IP_Address,  GETDATE(),  APP_NAME());\n"
						+ "			COMMIT TRANSACTION T1;\n" 
						+ "			ROLLBACK;\n" 
						+ "		END\n" 
						+ "    ELSE \n" 
						+ "    	BEGIN\n"
						+ "			INSERT INTO SC_OR_ACCLOG (SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, SAC_LOGON_DAY, SAC_PROGRAM)\n"
						+ "			VALUES (ORIGINAL_LOGIN(), @@SPID, 'logon',  @IP_Address,  GETDATE(),  APP_NAME() );\n"
						+ "		END;\n" 
						+ "END;	\n";
				stmt = sqlConnection.prepareStatement(sentence(cmd, null));
				stmt.execute();
				stmt.close();
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error registering logon trigger", e); //$NON-NLS-1$
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

	private void dropAccessControl()
			throws java.rmi.RemoteException, es.caib.seycon.ng.exception.InternalErrorException {
		PreparedStatement stmtCAC = null;
		PreparedStatement stmt = null;
		ResultSet rsetCAC = null;
		try {
			Connection sqlConnection = getConnection();

			// TRIGGERS DE LOGON Y LOGOFF
			// LOGON
			stmtCAC = sqlConnection.prepareStatement(
					sentence("select 1 from sys.server_triggers where name ='logon_audit_trigger'", null)); //$NON-NLS-1$
			rsetCAC = stmtCAC.executeQuery();

			boolean existeLogonTrigger = rsetCAC.next();

			if (existeLogonTrigger) {
				stmt = sqlConnection
						.prepareStatement(sentence("drop trigger logon_audit_trigger on all server", null)); //$NON-NLS-1$
				stmt.execute();
				stmt.close();
			}
			rsetCAC.close();
			stmtCAC.close();

		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error registering logon trigger", e); //$NON-NLS-1$
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

	private String sentence(String cmd) {
		return sentence(cmd, null);
	}

	protected String sentence(String cmd, Password pass) {
		if (debug)
			if (pass == null)
				log.info(cmd);
			else
				log.info(cmd.replace(quotePassword(pass), "******"));
		return cmd;
	}

	private String quotePassword(Password pass) {
		return pass.getPassword().replaceAll("'", "''");
	}

	public Collection<? extends LogEntry> getLogFromDate(Date From) throws RemoteException, InternalErrorException {
		SystemAccessControl dispatcherInfo = getServer().getDispatcherAccessControl(this.getSystem().getId());
		if (!dispatcherInfo.getEnabled())
			return null;

		log.info("LogLoader: loading since " + From);
		PreparedStatement stmt = null;
		ResultSet rset = null;
		// ArrayList<LogEntry> logs = new ArrayList<LogEntry>();
		Collection<LogEntry> logs = new LinkedList<LogEntry>();
		try {
			Connection sqlConnection = getConnection();
			// Obtenemos los logs
			String consulta = "select SAC_USER_ID, SAC_SESSION_ID, SAC_PROCESS, SAC_HOST, " //$NON-NLS-1$
					+ "SAC_LOGON_DAY, SAC_OS_USER, SAC_PROGRAM from SC_OR_ACCLOG ";
			if (From != null)
				consulta += "WHERE SAC_LOGON_DAY>=? "; //$NON-NLS-1$
			consulta += " order by SAC_LOGON_DAY "; //$NON-NLS-1$
			if (debug)
				log.info("LogLoader query: " + consulta);
			stmt = sqlConnection.prepareStatement(sentence(consulta));
			if (From != null)
				stmt.setTimestamp(1, new java.sql.Timestamp(From.getTime()));
			stmt.setMaxRows(100);
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
				log.setProtocol("oracle"); // De la tabla de serveis //$NON-NLS-1$

				// Usuario S.O.
				log.setUser(rset.getString(1));
				if (getServer().getAccountInfo(log.getUser(), getAgentName()) == null) {
					if (getServer().getAccountInfo(log.getUser().toUpperCase(), getAgentName()) != null)
						log.setUser(log.getUser().toUpperCase());
					else if (getServer().getAccountInfo(log.getUser().toLowerCase(), getAgentName()) != null)
						log.setUser(log.getUser().toLowerCase());
				}
				log.SessionId = rset.getString(2);
				log.info = "osUser: " + rset.getString(6) + " Program: " + rset.getString(7); // 7 //$NON-NLS-1$ //$NON-NLS-2$
																								// = program
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
				this.log.info("LogLoader: loaded " + log.getDate());
			}
			rset.close();
			stmt.close();
			return logs; // .toArray(new LogEntry[0]);
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException("Error getting roles", e); //$NON-NLS-1$
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

	public void updateAccessControl() throws RemoteException, InternalErrorException {
		SystemAccessControl dispatcherInfo = null; // Afegit AccessControl
		PreparedStatement stmt = null;
		PreparedStatement stmt2 = null;
		ResultSet rset = null;

		try {
			dispatcherInfo = getServer().getDispatcherAccessControl(this.getSystem().getId());
			// dispatcherInfo =
			// getServer().getSystemInfo(this.getSystem().getName());
			Connection sqlConnection = getConnection();

			if (dispatcherInfo == null) {
				dropAccessControl(); // desactivamos triggers
				throw new Exception(Messages.getString("OracleAgent.282") //$NON-NLS-1$
						+ this.getSystem().getName() + Messages.getString("OracleAgent.283")); //$NON-NLS-1$
			}

			if (dispatcherInfo.getEnabled()) { // getControlAccessActiu()
				// Lo activamos al final (!!)

				// Obtenemos las reglas de control de acceso
				List<AccessControl> controlAcces = dispatcherInfo.getControlAcces();
				// ArrayList<ControlAccess> controlAccess =
				// dispatcherInfo.getControlAcces();

				if (controlAcces == null || controlAcces.size() == 0) {
					// Eliminem les regles de control d'accés
					String cmd = "DELETE FROM SC_OR_CONACC"; //$NON-NLS-1$
					stmt = sqlConnection.prepareStatement(sentence(cmd));
					stmt.execute(cmd);
					stmt.close();
				} else {
					createAccessControlTables();

					stmt = sqlConnection.prepareStatement(
							sentence("SELECT SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM, SOC_CAC_ID from SC_OR_CONACC")); //$NON-NLS-1$
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
							AccessControl cac = controlAcces.get(i);
							if (cac != null && equalsControlAccess(cac, s_user, s_role, s_host, s_program, s_idcac)) {
								found = true; // ya existe: no lo creamos
								controlAcces.set(i, null);
							}
						}

						if (!found) {// No l'hem trobat: l'esborrem
							String condicions = ""; //$NON-NLS-1$
							// SOC_USER,SOC_ROLE,SOC_HOST,SOC_PROGRAM
							int param = 1;
							if (s_user == null)
								condicions += " AND SOC_USER is null "; //$NON-NLS-1$
							else {
								condicions += " AND SOC_USER=? "; //$NON-NLS-1$
							}
							if (s_role == null)
								condicions += " AND SOC_ROLE is null "; //$NON-NLS-1$
							else
								condicions += " AND SOC_ROLE=? "; //$NON-NLS-1$
							stmt2 = sqlConnection
									.prepareStatement(sentence("DELETE SC_OR_CONACC WHERE SOC_HOST=? AND SOC_PROGRAM=? " //$NON-NLS-1$
											+ condicions));
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
							AccessControl cac = controlAcces.get(i);
							stmt2 = sqlConnection.prepareStatement(sentence(
									"INSERT INTO SC_OR_CONACC(SOC_USER, SOC_ROLE, SOC_HOST, SOC_PROGRAM, SOC_CAC_ID, SOC_HOSTNAME) VALUES (?,?,?,?,?,?)")); //$NON-NLS-1$
							stmt2.setString(1, cac.getGenericUser());
							stmt2.setString(2, cac.getRoleDescription());
							stmt2.setString(3, cac.getRemoteIp());
							stmt2.setString(4, cac.getProgram());
							stmt2.setString(5, cac.getId().toString());
							stmt2.setString(6, cac.getHostName());
							stmt2.execute();
							stmt2.close();
						}
					}
				}
				// Los activamos tras propagar las reglas (!!)
				createAccessControl();

			} else { // Desactivamos los triggers
				dropAccessControl();
			}
		} catch (SQLException e) {
			handleSQLException(e);
		} catch (Exception e) {
			e.printStackTrace();
			throw new InternalErrorException(Messages.getString("OracleAgent.293"), e); //$NON-NLS-1$
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

	private boolean equalsControlAccess(AccessControl cac, String s_user,
			String s_role, String s_host, String s_program, String s_cac_id) {

		// Si no es la misma fila, no continuamos (AÑADIDO POR TRAZAS)
		if (!s_cac_id.equals(cac.getId()))
			return false; // idControlAcces canviat per getId

		// User o rol ha de ser nulo (uno de los dos)
		if (s_user == null) {
			if (cac.getGenericUser() != null)
				return false;
		} else {
			if (!s_user.equals(cac.getGenericUser()))
				return false;
		}
		if (s_role == null) {
			if (cac.getRoleDescription() != null)
				return false;
		} else {
			if (!s_role.equals(cac.getRoleDescription()))
				return false;
		}
		if (s_host == null) {
			if (cac.getHostId() != null)
				return false;
		} else {
			if (!s_host.equals(cac.getHostId()))
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

}