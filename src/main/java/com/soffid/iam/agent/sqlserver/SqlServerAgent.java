package com.soffid.iam.agent.sqlserver;

import java.rmi.RemoteException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Collection;
import java.util.Hashtable;
import java.util.LinkedList;
import java.util.List;

import com.soffid.iam.ServiceLocator;
import com.soffid.iam.api.Account;
import com.soffid.iam.api.AccountStatus;
import com.soffid.iam.api.Group;
import com.soffid.iam.api.Password;
import com.soffid.iam.api.Role;
import com.soffid.iam.api.RoleGrant;
import com.soffid.iam.api.System;
import com.soffid.iam.api.User;
import com.soffid.iam.service.DispatcherService;
import com.soffid.iam.sync.agent.Agent;
import com.soffid.iam.sync.intf.ReconcileMgr2;
import com.soffid.iam.sync.intf.RoleMgr;
import com.soffid.iam.sync.intf.UserMgr;

import es.caib.seycon.ng.exception.InternalErrorException;

/**
 * Agente SEYCON para gestionar bases de datos SQL Server
 * <P>
 */

public class SqlServerAgent extends Agent implements UserMgr, RoleMgr,
		ReconcileMgr2 {
	/** Usuario SQL Server */
	transient String user;
	/** Contraseña SQL Server */
	transient Password password;
	/** Cadena de conexión a la base de datos */
	transient String db;
	/** Valor que activa o desactiva el debug */
	transient boolean debug;
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
	 *            <LI>1 = contraseña</LI> <LI>2 = cadena de conexión a la
	 *            base de datos</LI> <LI>3 = contraseña con la que se protegerán
	 *            los roles</LI>
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
			log.info("user: "+user);
			log.info("password: ********");
			log.info("db: "+db);
			log.info("createChild: "+createChild);
			log.info("debug: "+debug);
		}

		String instance = null;
		int i = db.toLowerCase().indexOf(";databasename=");
		if (i >= 0)
		{
			int j = db.indexOf(";", i+1);
			if (j < 0)
				instance = db.substring(i+14);
			else
				instance = db.substring(i+14, j);
		}
		if (instance == null)
		{
			instance = "master";
			db = db + ";databaseName=master";
		}

		if (debug) log.info("Database instance = "+instance);
		// Verifiramos que estén creadas las tablas y los triggers
		if (createChild && instance.equalsIgnoreCase("master"))
		{
			if (debug) log.info("Creating child dispatchers");
			createChildDispatchers();
		}
	}

	private void createChildDispatchers() throws InternalErrorException {
			PreparedStatement stmt = null;
			ResultSet rset = null;

			DispatcherService svc = ServiceLocator.instance().getDispatcherService();
			try {
				Connection sqlConnection = getConnection();

				stmt = sqlConnection
						.prepareStatement("SELECT name from sys.databases"); //$NON-NLS-1$
				rset = stmt.executeQuery();
				// Determinar si el usuario está o no activo
				// Si no existe darlo de alta
				while (rset.next()) {
					String name = rset.getString(1);
					if (! name.equals("master"))
					{
						System d = svc.findDispatcherByName(getAgentName()+"/"+name);
						if (d == null)
						{
							d = new System( getSystem() );
							d.setId(null);
							d.setName(d.getName()+"/"+name);
							
							String db = getSystem().getParam2();
							int i = db.indexOf(";databaseName=");
							if (i >= 0)
							{
								int j = db.indexOf(";", i+1);
								if (j < 0)
									db = db.substring(0,i);
								else
									db = db.substring(0,i)+db.substring(j);
							}
							db = db + ";databaseName="+name;
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
	}

	/**
	 * Liberar conexión a la base de datos. Busca en el hash de conexiones
	 * activas alguna con el mismo nombre que el agente y la libera. A
	 * continuación la elimina del hash. Se invoca desde el método de gestión de
	 * errores SQL.
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
	 * conexión con la base de datos y la registra en el hash de conexiones
	 * activas
	 * 
	 * @return conexión SQL asociada.
	 * @throws InternalErrorException
	 *             algún error en el proceso de conexión
	 */
	public Connection getConnection() throws InternalErrorException {
		Connection conn = (Connection) hash.get(this.getSystem().getName());
		if (conn == null) {
			try {
				DriverManager
						.registerDriver(new com.microsoft.sqlserver.jdbc.SQLServerDriver());
				// Connect to the database
				conn = DriverManager.getConnection(db, user,
							password.getPassword());
				hash.put(this.getSystem().getName(), conn);
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
		if (debug) log.warn(this.getSystem().getName() + " SQL Exception: ", e); //$NON-NLS-1$
		releaseConnection();
		throw new InternalErrorException("Error executing statement", e);
	}

	public void updateUser(Account account)
			throws java.rmi.RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
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
				log.info("Checking login "+account.getName());
			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement("SELECT name FROM sys.syslogins WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (!rset.next()) {
				if (debug)
					log.info("Account "+account.getName()+" not found");
				if ( account.getStatus() != AccountStatus.REMOVED)
				{
					stmt.close();
					
					Password pass = getServer().getOrGenerateUserPassword(account.getName(),
							getSystem().getName());
					
					String cmd;
					if (! account.getName().contains("\\"))
					{
						if (debug)
							log.info("Creating login "+account.getName()+" from locally");
						Password p = getServer().getOrGenerateUserPassword(account.getName(), account.getSystem());
						if ( p == null)
							cmd = "CREATE LOGIN [" + account.getName() + "]"; //$NON-NLS-1$
						else
							cmd = "CREATE LOGIN [" + account.getName() + "] WITH PASSWORD = '"+p.getPassword().replaceAll("'", "''")+"'"; //$NON-NLS-1$
					}
					else
					{
						if (debug)
							log.info("Creating login "+account.getName()+" from windows");
						cmd = "CREATE LOGIN [" + account.getName() + "] FROM WINDOWS"; //$NON-NLS-1$
					}
					if (debug) log.info(cmd);
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute();
				}
			}
			rset.close();
			stmt.close();

			// Comprobar si el usuario existe
			stmt = sqlConnection
					.prepareStatement("SELECT name FROM sys.sysusers WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (debug)
				log.info("Checking user "+account.getName()+"");
			if (!rset.next()) {
				if ( ! account.isDisabled())
				{
					if (debug)
						log.info("Creating user "+account.getName()+"");
					stmt.close();
					
					String cmd;
					cmd = "CREATE USER [" + account.getName() + "]"; //$NON-NLS-1$
					if (debug) log.info(cmd);
					stmt = sqlConnection.prepareStatement(cmd);
					stmt.execute();
				}
			}
			else
			{
				log.info("Found user "+rset.getString(1));
				if ( account.getStatus() == AccountStatus.REMOVED)
				{
					if (debug) log.info("DROP USER ["+account.getName()+"]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("DROP USER ["+account.getName()+"]");
					stmt2.close();
				}
				else if ( account.isDisabled())
				{
					if (debug) log.info("REVOKE CONNECT FROM ["+account.getName()+"]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("REVOKE CONNECT FROM ["+account.getName()+"]");
					stmt2.close();
				} else {
					if (debug) log.info("GRANT CONNECT TO ["+account.getName()+"]");
					stmt2 = sqlConnection.createStatement();
					stmt2.execute("GRANT CONNECT TO ["+account.getName()+"]");
					stmt2.close();
				}
				
			}
			if ( account.getStatus() == AccountStatus.REMOVED || account.isDisabled())
				return;
						
			// System.out.println ("Usuario "+user+" ya existe");
			rset.close();
			stmt.close();

			if (debug)
				log.info("Checking grants "+account.getName()+" ");

			// Eliminar los roles que sobran
			stmt = sqlConnection
					.prepareStatement("SELECT DP1.name AS DatabaseRoleName,   \n" + 
							"   isnull (DP2.name, 'No members') AS DatabaseUserName   \n" + 
							" FROM sys.database_role_members AS DRM  \n" + 
							" JOIN sys.database_principals AS DP1  \n" + 
							"   ON DRM.role_principal_id = DP1.principal_id  \n" + 
							" JOIN sys.database_principals AS DP2  \n" + 
							"   ON DRM.member_principal_id = DP2.principal_id  \n" + 
							"WHERE DP1.type = 'R' AND DP2.name=?\n" + 
							"ORDER BY DP1.name;  "); //$NON-NLS-1$
			stmt.setString(1, account.getName());
			rset = stmt.executeQuery();
			stmt2 = sqlConnection.createStatement();
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
				if (!found)
					stmt2.execute("EXEC sp_droprolemember ["+role+"], ["+account.getName()+"];"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
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
			for (i = 0; /* active && */groupsAndRoles != null
					&& i < groupsAndRoles.length; i++) {
				if (groupsAndRoles[i] != null) {
					stmt2.execute("EXEC sp_addrolemember ["+groupsAndRoles[i]+"], ["+account.getName()+"];"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
				}
			}
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

	public void updateUserPassword(String user, User arg1, Password password,
			boolean mustchange)
			throws es.caib.seycon.ng.exception.InternalErrorException {
		updateUserPassword(user, password);
		
	}
	
	public void updateUserPassword(String user, Password password) throws InternalErrorException
	{
		if ( user.contains("\\"))
			return;
		PreparedStatement stmt = null;
		String cmd = ""; //$NON-NLS-1$
		try {
			// Comprobar si el usuario existe
			Connection sqlConnection = getConnection();
			stmt = sqlConnection
					.prepareStatement("SELECT name from sys.syslogins " + //$NON-NLS-1$
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
	public String[] concatUserGroupsAndRoles(Collection<Group> groups,
			Collection<RoleGrant> roles) {
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
	 * @see es.caib.seycon.RoleMgr#UpdateRole(java.lang.String,
	 * java.lang.String)
	 */
	public void updateRole(Role ri) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
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
			throw new InternalErrorException(
					Messages.getString("OracleAgent.ErrorUpdatingRole"), e); //$NON-NLS-1$
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
				if (rset.next())
				{
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

	public void removeUser(String arg0) throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account account = getServer().getAccountInfo(arg0, getAgentName());
		if (account == null){
			account = new Account();
			account.setName(arg0);
			account.setSystem(getAgentName());
			account.setStatus(AccountStatus.REMOVED);
		}
		updateUser(account);
	}

	public void updateUser(String nom, String descripcio)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		Account acc = getServer().getAccountInfo(nom, getAgentName());
		if (acc == null)
		{
			acc = new Account();
			acc.setName(nom);
			acc.setDescription(descripcio);
			acc.setStatus(AccountStatus.REMOVED);
		}
		updateUser(acc);
	}

	public void updateUser(Account account, User user)
			throws RemoteException,
			es.caib.seycon.ng.exception.InternalErrorException {
		updateUser(account);
	}

	public List<String> getAccountsList() throws RemoteException,
			InternalErrorException {
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

			stmt = sqlConnection
					.prepareStatement("SELECT name FROM sys.sysusers"); //$NON-NLS-1$
			rset = stmt.executeQuery();
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
					.prepareStatement("SELECT name, hasdbaccess FROM sys.sysusers WHERE name=?"); //$NON-NLS-1$
			stmt.setString(1, userAccount);
			rset = stmt.executeQuery();
			// Determinar si el usuario está o no activo
			// Si no existe darlo de alta
			if (rset.next()) {
				int access = rset.getInt(2);
				Account account = new Account ();
				account.setName(userAccount);
				account.setName(userAccount);
				account.setSystem(getAgentName());
				account.setDisabled( access == 0 );
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
					.prepareStatement("SELECT name from sys.database_principals where type = 'R'"); //$NON-NLS-1$
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

	public Role getRoleFullInfo(String roleName) throws RemoteException,
			InternalErrorException {
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

	public List<RoleGrant> getAccountGrants(String userAccount)
			throws RemoteException, InternalErrorException {
		LinkedList<RoleGrant> roles = new LinkedList<RoleGrant>();
		PreparedStatement stmt = null;
		ResultSet rset = null;

		try {
			Connection sqlConnection = getConnection();

			stmt = sqlConnection
					.prepareStatement("SELECT DP1.name AS DatabaseRoleName,   \n" + 
							"   isnull (DP2.name, 'No members') AS DatabaseUserName   \n" + 
							" FROM sys.database_role_members AS DRM  \n" + 
							" JOIN sys.database_principals AS DP1  \n" + 
							"   ON DRM.role_principal_id = DP1.principal_id  \n" + 
							" JOIN sys.database_principals AS DP2  \n" + 
							"   ON DRM.member_principal_id = DP2.principal_id  \n" + 
							"WHERE DP1.type = 'R' AND DP2.name=?\n" + 
							"ORDER BY DP1.name;  "); //$NON-NLS-1$
			stmt.setString(1,  userAccount);
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
