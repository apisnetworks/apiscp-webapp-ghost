<?php
	declare(strict_types=1);
	/**
	 *  +------------------------------------------------------------+
	 *  | apnscp                                                     |
	 *  +------------------------------------------------------------+
	 *  | Copyright (c) Apis Networks                                |
	 *  +------------------------------------------------------------+
	 *  | Licensed under Artistic License 2.0                        |
	 *  +------------------------------------------------------------+
	 *  | Author: Matt Saladna (msaladna@apisnetworks.com)           |
	 *  +------------------------------------------------------------+
	 */

	use Module\Support\Webapps;
	use Module\Support\Webapps\Traits\PublicRelocatable;

	/**
	 * Ghost management
	 *
	 * A blogging platform built on Node
	 *
	 * @package core
	 */
	class Ghost_Module extends Webapps
	{
		// via https://ghost.org/faq/node-versions/
		const DEFAULT_NODE = '12';
		use PublicRelocatable {
			getAppRoot as getAppRootReal;
		}
		const APP_NAME = 'Ghost';
		const GHOST_CLI = 'ghost';
		const DEFAULT_VERSION_LOCK = 'major';

		const NODE_VERSIONS = [
			'0'     => self::DEFAULT_NODE,
			'4.0'   => '12.10.0',
			'4.5'   => '12.22.1',
			'4.6'   => '14.16.1',
			'4.21'  => '14.18.0',
			'5.0'   => '16.19',
		];

		public function plugin_status(string $hostname, string $path = '', string $plugin = null)
		{
			return error('not supported');
		}

		public function uninstall_plugin(string $hostname, string $path, string $plugin, bool $force = false): bool
		{
			return error('not supported');
		}

		public function disable_all_plugins(string $hostname, string $path = ''): bool
		{
			return error('not supported');
		}


		public function restart(string $hostname, string $path = ''): bool
		{
			if (!$approot = $this->getAppRoot($hostname, $path)) {
				return false;
			}

			return \Module\Support\Webapps\Passenger::instantiateContexted($this->getAuthContext(),
				[$approot, 'nodejs'])->restart();
		}

		/**
		 * Get app root for Ghost
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return null|string
		 */
		protected function getAppRoot(string $hostname, string $path = ''): ?string
		{
			return $this->getAppRootReal($hostname, $path);
		}

		/**
		 * Install Ghost into a pre-existing location
		 *
		 * @param string $hostname domain or subdomain to install Laravel
		 * @param string $path     optional path under hostname
		 * @param array  $opts     additional install options
		 * @return bool
		 */
		public function install(string $hostname, string $path = '', array $opts = array()): bool
		{
			if (!$this->mysql_enabled()) {
				return error('%(what)s must be enabled to install %(app)s',
					['what' => 'MySQL', 'app' => static::APP_NAME]);
			}
			$available = null;
			if (!$this->hasMemoryAllowance(768, $available)) {
				return error("%(app)s requires at least %(min)d MB memory, `%(found)d' MB provided for account",
					['app' => 'Ghost', 'min' => 768, 'found' => $available]);
			}
			if (!$this->hasStorageAllowance(500, $available)) {
				return error("%(app)s requires at least %(min)d MB storage. Only %(found).2f' MB provided for account",
					['app' => 'Ghost', 'min' => 500, 'found' => $available]);
			}

			if (!$this->ssh_enabled()) {
				return error('Ghost requires ssh service to be enabled');
			}

			// assume all Ghost installs will be located in a parent directory
			// once installed, relink the domain/subdomain to $docroot + /public
			// also block installing under a path, because this would require either relocating
			// Ghost outside any document root, e.g. /var/www/<hostname>-<path>-ghost and making
			// a symlink, which fails once the parent document root moves (must use relative symlinks)
			// and clutters up wherever they get located... no sound solution
			if ($path) {
				return error('Ghost may only be installed directly on a subdomain or domain without a child path, e.g. https://domain.com but not https://domain.com/ghost');
			}

			if (!($docroot = $this->getDocumentRoot($hostname, $path))) {
				return error("failed to normalize path for `%s'", $hostname);
			}

			if (!$this->parseInstallOptions($opts, $hostname, $path)) {
				return false;
			}

			if (!$this->platformVersionCheck((string)$opts['version'])) {
				return error("Ghost %s cannot be installed on this platform", $opts['version']);
			}

			$nodeVersion = $this->validateNode((string)$opts['version'], $opts['user'] ?? null);
			$this->node_make_default($nodeVersion, $docroot);

			$args['version'] = $opts['version'];

			$db = Webapps\DatabaseGenerator::mysql($this->getAuthContext(), $hostname);
			$db->hostname = '127.0.0.1';
			$db->connectionLimit = max($db->connectionLimit, 15);

			if (!$db->create()) {
				return false;
			}

			$args['dbname'] = $db->database;
			$args['dbuser'] = $db->username;
			$args['dbpassword'] = $db->password;

			$fqdn = $this->web_normalize_hostname($hostname);
			$args['uri'] = rtrim($fqdn . '/' . $path, '/');
			$args['proto'] = empty($opts['ssl']) ? 'http://' : 'https://';
			$args['debug'] = is_debug() ? '-V' : null;
			if (is_debug()) {
				warn("Disabling debug mode as it causes a maxBuffer exceeded error");
				$args['debug'] = null;
			}
			// use localhost.localdomain, which is an alias to 127.0.0.1;
			// ghost looks for "mysqld" if dbhost is localhost or 127.0.0.1;
			// this isn't present in a synthetic root
			$ret = $this->_exec($docroot,
				'nvm exec --silent ghost install %(debug)s --process=local --no-prompt --no-stack --no-start --no-color --db=mysql --dbhost=localhost.localdomain --dbuser=%(dbuser)s --dbpass=%(dbpassword)s ' .
				'--dbname=%(dbname)s --no-setup-linux-user --no-setup-nginx --url=%(proto)s%(uri)s --mail=sendmail %(version)s',
				$args);

			if (!$ret['success']) {
				info('removing temporary files');
				$this->file_delete($docroot, true);
				$db->rollback();

				return error('failed to download Ghost v%s: %s - possibly out of storage space?', $args['version'],
					$ret['stdout']);
			}

			$wrapper = empty($opts['user']) ? $this : \apnscpFunctionInterceptor::factory(Auth::context($opts['user'],
				$this->site));

			$wrapper->node_make_default($nodeVersion, $docroot);

			if (!isset($opts['password'])) {
				$opts['password'] = \Opcenter\Auth\Password::generate(10);
				info("autogenerated password `%s'", $opts['password']);
			}

			$username = $this->user_getpwnam($opts['user'] ?? $this->username)['gecos'] ?: $this->username;
			info("setting displayed name to `%s'", $username);
			$opts['url'] = rtrim($hostname . '/' . $path, '/');

			if (!$this->fixSymlink($docroot)) {
				return error("Failed to correct current/ symlink in `%s'", $docroot);
			}

			$this->fixThemeLink($docroot);

			if (null === ($docroot = $this->remapPublic($hostname, $path))) {
				// it's more reasonable to fail at this stage, but let's try to complete
				return error("Failed to remap Ghost to public/, manually remap from `%s' - Ghost setup is incomplete!",
					$docroot);
			}

			$approot = $this->getAppRoot($hostname, $path);
			// @todo migrate cache management to reconfigure method
			$config = [
				'useMinFiles'              => 'true',
				'caching.frontend.maxAge'  => 120,
				'logging.rotation.enabled' => 'true',
				'mail.transport'           => 'sendmail',
				// frontend caches + leave 5 for update/admin
				'database.pool.max'        => 5,
				'paths.contentPath'        => "${approot}/content"
			];

			foreach ($config as $c => $v) {
				$ret = $this->_exec($approot, 'nvm exec ghost config set %(c)s %(v)s', ['c' => $c, 'v' => $v]);
				if (!$ret['success']) {
					info('removing temporary files');
					$this->file_delete($docroot, true);
					$db->rollback();
					return error("Failed to set configuration `%s': %s", $c, coalesce($ret['stderr'], $ret['stdout']));
				}
			}

			foreach (['tmp', 'public', 'logs'] as $dir) {
				($this->file_create_directory("${approot}/${dir}") &&
					$this->file_chown("${approot}/${dir}", $opts['user'] ?? $this->username)
				) || warn("failed to create application directory `%s/%s'", $docroot, $dir);
			}


			$this->initializeMeta($docroot, $opts);

			$this->linkConfiguration($approot, 'production');

			if (!$this->file_put_file_contents($docroot . '/.htaccess',
				'# Enable caching' . "\n" .
				'UnsetEnv no-cache' . "\n" .
				'PassengerEnabled on' . "\n" .
				'PassengerAppEnv production' . "\n" .
				'PassengerStartupFile current/index.js' . "\n" .
				'PassengerAppType node' . "\n" .
				'PassengerNodejs ' . $this->getNodeCommand($nodeVersion, $opts['user'] ?? null) . "\n" .
				'PassengerAppRoot ' . $approot . "\n"
			)) {
				return error('failed to create .htaccess control - Ghost is not properly setup');
			}

			$this->node_do($nodeVersion, 'npm install -g knex-migrator');
			$ret = $this->_exec("${approot}/current", 'nvm exec knex-migrator init', ['NODE_VERSION' => $nodeVersion]);
			if (!$ret['success']) {
				return error('Failed to create initial database configuration - knex-migrator failed: %s',
					coalesce($ret['stderr'], $ret['stdout']));
			}
			if (!$this->migrate($approot)) {
				return error('Failed to migrate database configuration - Ghost installation incomplete');
			}
			$this->change_admin($hostname, $path, [
				'email'    => $opts['email'],
				'password' => $opts['password'],
				'name'     => $username
			]);

			$this->notifyInstalled($hostname, $path, $opts);

			return info('%(app)s installed - confirmation email with login info sent to %(email)s',
				['app' => static::APP_NAME, 'email' => $opts['email']]);
		}

		/**
		 * Verify Node LTS is installed
		 *
		 * @param string|null $version optional version to compare against
		 * @param string|null $user
		 * @return bool
		 */
		protected function validateNode(string $version = self::DEFAULT_NODE, string $user = null): ?string
		{
			if ($user) {
				$afi = \apnscpFunctionInterceptor::factory(Auth::context($user, $this->site));
			}
			$wrapper = $afi ?? $this;
			$nodeVersion = \Opcenter\Versioning::satisfy($version, self::NODE_VERSIONS);
			if (!$wrapper->node_installed($nodeVersion) && !$wrapper->node_install($nodeVersion)) {
				error('failed to install Node %s', $nodeVersion);
				return null;
			}
			$wrapper->node_do($nodeVersion, 'nvm use --delete-prefix');
			$ret = $wrapper->node_do($nodeVersion, 'npm install -g ghost-cli');
			if (!$ret['success']) {
				error('failed to install ghost-cli: %s', $ret['stderr'] ?? 'UNKNOWN ERROR');
				return null;
			}
			$home = $this->user_get_home($user);
			$stat = $this->file_stat($home);
			if (!$stat || !$this->file_chmod($home, decoct($stat['permissions']) | 0001)) {
				error("failed to query user home directory `%s' for user `%s'", $home, $user);
				return null;
			}

			return $nodeVersion;
		}

		private function _exec(?string $path, $cmd, array $args = array(), $env = array())
		{
			// client may override tz, propagate to bin
			if (!is_array($args)) {
				$args = func_get_args();
				array_shift($args);
			}
			$user = $this->username;
			if ($path) {
				$cmd = 'cd %(path)s && /bin/bash -ic -- ' . escapeshellarg($cmd);
				$args['path'] = $path;
				$user = $this->file_stat($path)['owner'] ?? $this->username;
			}

			$ret = $this->pman_run($cmd, $args,
				$env + [
					'NVM_DIR'  => $this->user_get_home($user),
					'PATH'     => getenv('PATH') . PATH_SEPARATOR . '~/node_modules/.bin',
					'NODE_ENV' => 'production'
				], ['user' => $user]);
			if (!strncmp(coalesce($ret['stderr'], $ret['stdout']), 'Error:', strlen('Error:'))) {
				// move stdout to stderr on error for consistency
				$ret['success'] = false;
				if (!$ret['stderr']) {
					$ret['stderr'] = $ret['stdout'];
				}

			}

			return $ret;
		}

		/**
		 * Get installed version
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return string version number
		 */
		public function get_version(string $hostname, string $path = ''): ?string
		{
			if (!$this->valid($hostname, $path)) {
				return null;
			}
			if ($hostname[0] !== '/') {
				$approot = $this->getAppRoot($hostname, $path);
			} else {
				$approot = Webapps\App\Loader::fromDocroot('ghost', $hostname, $this->getAuthContext())->getAppRoot();
			}
			$path = $this->domain_fs_path($approot . '/current/package.json');
			clearstatcache(true, \dirname($path));
			clearstatcache(true, $path);
			if (!file_exists($path)) {
				warn('missing package.json from Ghost root - cannot detect version');

				return null;
			}

			return json_decode(file_get_contents($path))->version;
		}

		/**
		 * Location is a valid Ghost install
		 *
		 * @param string $hostname or $docroot
		 * @param string $path
		 * @return bool
		 */
		public function valid(string $hostname, string $path = ''): bool
		{
			if (!IS_CLI) {
				return $this->query('ghost_valid', $hostname, $path);
			}

			if ($hostname[0] === '/') {
				if (!($path = realpath($this->domain_fs_path($hostname)))) {
					return false;
				}
				$approot = \dirname($path);
			} else {
				$approot = $this->getAppRoot($hostname, $path);
				if (!$approot) {
					return false;
				}
				$approot = $this->domain_fs_path($approot);
			}
			if (is_link($approot . '/current') && readlink($approot . '/current')[0] === '/') {
				$this->fixSymlink($this->file_unmake_path($approot));
			}

			return file_exists($approot . '/current/core/server/ghost-server.js') || file_exists($approot . '/current/core/server/GhostServer.js');
		}

		/**
		 * Relink current/ from absolute to relative symlink
		 *
		 * @param string $approot
		 * @return bool
		 */
		private function fixSymlink(string $approot): bool
		{
			$path = $this->domain_fs_path("${approot}/current");
			clearstatcache(true, $path);
			if (!is_link($path)) {
				return error("${approot}/current missing - can't relink");
			}
			$link = readlink($path);
			if ($link[0] !== '/') {
				// relative link
				$stat = $this->file_stat("${approot}/current");

				return !empty($stat['referent']) ? true : error("${approot}/current does not point to an active Ghost install");
			}

			if (0 !== strpos($link, $approot)) {
				return false;
			}
			// debugging code...
			if (!$this->file_delete($approot . '/current') || !$this->file_symlink($link, $approot . '/current')) {
				return false;
			}

			return $this->file_chown_symlink($approot . '/current', $this->file_stat($approot)['owner']);
		}

		/**
		 * Correct theme link when Ghost is installed in primary docroot
		 *
		 * @param string $approot
		 * @return bool
		 */
		private function fixThemeLink(string $approot): bool
		{
			$path = $this->domain_fs_path("${approot}/content/themes");
			if (!file_exists($path)) {
				return warn('Cannot correct theme symlinks, cannot find theme path');
			}
			$dh = opendir($path);
			while (false !== ($file = readdir($dh))) {
				if ($file === '.' || $file === '..') {
					continue;
				}
				if (!is_link("${path}/${file}")) {
					continue;
				}
				$link = readlink("${path}/${file}");
				if (0 !== strpos($link . '/', Web_Module::MAIN_DOC_ROOT . '/')) {
					continue;
				}
				$localpath = $this->file_unmake_path("${path}/${file}");
				$this->file_delete($localpath) && $this->file_symlink($approot . substr($link,
						strlen(Web_Module::MAIN_DOC_ROOT)),
					$localpath);
			}
			closedir($dh);

			return true;
		}

		/**
		 * Get path to active Node
		 *
		 * @param string|null $version
		 * @param string|null $user
		 * @return null|string
		 */
		protected function getNodeCommand(string $version = 'lts', string $user = null): ?string
		{
			if ($user) {
				$afi = \apnscpFunctionInterceptor::factory(Auth::context($user, $this->site));
			}
			$ret = ($afi ?? $this)->node_do($version, 'which node');

			return $ret['success'] ? trim($ret['output']) : null;
		}

		/**
		 * Migrate database configuration to current/
		 *
		 * @param string $approot
		 * @param string $appenv
		 * @return bool
		 */
		private function linkConfiguration(string $approot, string $appenv = 'production'): bool
		{
			$stat = $this->file_stat($approot . "/current/config.${appenv}.json");
			if ($stat) {
				if ($stat['link']) {
					return true;
				}
				$this->file_delete($approot . "/current/config.${appenv}.json");
			}

			return $this->file_symlink($approot . "/config.${appenv}.json",
					$approot . "/current/config.${appenv}.json") ||
				warn("failed to link configuration ${approot}/config.${appenv}.json to current/");
		}

		/**
		 * Migrate Ghost database
		 *
		 * @param string $approot
		 * @param string $appenv optional app environment to source DB config
		 * @return bool
		 */
		private function migrate(string $approot, string $appenv = 'production'): bool
		{
			$this->linkConfiguration($approot, $appenv);
			$this->_exec("$approot/current", 'nvm exec which knex-migrator > /dev/null || nvm exec npm install -g knex-migrator', [],
				['NODE_VERSION' => $this->node_get_default($approot)]);
			$ret = $this->_exec("${approot}/current", 'nvm exec knex-migrator migrate', [], ['NODE_VERSION' => $this->node_get_default($approot)]);

			return $ret['success'] ?: error("failed to migrate database in `%s': %s", $approot,
				coalesce($ret['stderr'], $ret['stdout']));
		}

		/**
		 * Change Ghost admin credentials
		 *
		 * Common fields include: password, email, name; email doubles as login
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param array  $fields
		 * @return bool
		 */
		public function change_admin(string $hostname, string $path, array $fields): bool
		{
			$docroot = $this->getAppRoot($hostname, $path);
			if (!$docroot) {
				return warn('failed to change administrator information');
			}
			$admin = $this->get_admin($hostname, $path);

			if (!$admin) {
				return error('cannot determine admin of Ghost install');
			}

			if (isset($fields['password'])) {
				if (!\Opcenter\Auth\Password::strong($fields['password'])) {
					return false;
				}
				$fields['password'] = password_hash($fields['password'], PASSWORD_BCRYPT, ['cost' => 10]);
			}
			if (isset($fields['name'])) {
				$fields['slug'] = str_slug($fields['name']);
			}

			$db = $this->connectDB($hostname, $path);
			$q = "UPDATE users SET status = 'active'";
			foreach (['password', 'email', 'name', 'slug'] as $field) {
				if (!isset($fields[$field])) {
					continue;
				}
				$q .= ", {$field} = '" . $db->escape_string($fields[$field]) . "'";
			}
			$q .= " WHERE email = '" . $admin . "'";
			if (false === $db->query($q) || $db->affected_rows() < 1) {
				return error("Failed to change admin user `%s'", $admin);
			}
			if (isset($fields['email'])) {
				info('user login changed to %s', $fields['email']);
			}
			if (isset($fields['password'])) {
				info("user `%s' password changed", $fields['email'] ?? $admin);
			}

			return true;
		}

		/**
		 * Get the primary admin for a WP instance
		 *
		 * @param string      $hostname
		 * @param null|string $path
		 * @return string admin or false on failure
		 */
		public function get_admin(string $hostname, string $path = ''): ?string
		{
			$mysql = $this->connectDB($hostname, $path);
			$rs = $mysql->query('SELECT email FROM users WHERE id = 1');
			if (!$rs || $rs->num_rows < 1) {
				return null;
			}

			return $rs->fetch_object()->email;
		}

		private function connectDB($hostname, $path): \MySQL
		{
			$dbconfig = $this->db_config($hostname, $path);
			$host = $dbconfig['host'] === 'localhost.localdomain' ? '127.0.0.1' : $dbconfig['host'];

			return \MySQL::stub()->connect($host, $dbconfig['user'], $dbconfig['password'], $dbconfig['db']);
		}

		/**
		 * Get database configuration for a blog
		 *
		 * @param string $hostname domain or subdomain of wp blog
		 * @param string $path     optional path
		 * @return bool|array
		 */
		public function db_config(string $hostname, string $path = '')
		{
			$approot = $this->getAppRoot($hostname, $path);
			if (!$approot) {
				error('failed to determine Ghost config - ' . $approot);

				return [];
			}
			foreach (['development', 'production'] as $env) {
				$path = "${approot}/config.${env}.json";
				if ($this->file_exists($path)) {
					// @todo unify config into a consistent object
					$json = json_decode($this->file_get_file_contents($path), true)['database']['connection'];
					if (!$json) {
						continue;
					}
					$json['db'] = $json['database'];
					$json['prefix'] = '';

					return $json;
				}
			}

			return [];
		}

		/**
		 * Install and activate plugin
		 *
		 * @param string $hostname domain or subdomain of wp install
		 * @param string $path     optional path component of wp install
		 * @param string $plugin   plugin name
		 * @param string $version  optional plugin version
		 * @return bool
		 */
		public function install_plugin(
			string $hostname,
			string $path,
			string $plugin,
			string $version = 'stable'
		): bool {
			return error('not supported');
		}

		/**
		 * Uninstall WP from a location
		 *
		 * @param        $hostname
		 * @param string $path
		 * @param string $delete remove all files under docroot
		 * @return bool
		 */
		public function uninstall(string $hostname, string $path = '', string $delete = 'all'): bool
		{
			$this->kill($hostname, $path);

			return parent::uninstall($hostname, $path, $delete);
		}

		/**
		 * Update core, plugins, and themes atomically
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param string $version
		 * @return bool
		 */
		public function update_all(string $hostname, string $path = '', string $version = null): bool
		{
			return $this->update($hostname, $path, $version) || error('failed to update all components');
		}

		/**
		 * Update Ghost to latest version
		 *
		 * @param string $hostname domain or subdomain under which WP is installed
		 * @param string $path     optional subdirectory
		 * @param string $version
		 * @return bool
		 */
		public function update(string $hostname, string $path = '', string $version = null): bool
		{
			$approot = $this->getAppRoot($hostname, $path);
			if (!$approot) {
				return error('update failed');
			}

			if (!$version) {
				$version = \Opcenter\Versioning::nextVersion($this->get_versions(),
					$this->get_version($hostname, $path));
			} else if (!\Opcenter\Versioning::valid($version)) {
				return error('invalid version number, %s', $version);
			}

			if (!$this->platformVersionCheck($version)) {
				return error("Ghost %s cannot be installed on this platform", $version);
			}

			$this->file_chmod($approot, 705);

			$oldversion = $this->get_version($hostname, $path);
			if ($oldversion === $version) {
				return info("Ghost is already at current version `%s'", $version);
			}

			if (\Opcenter\Versioning::asMajor($version) !== \Opcenter\Versioning::asMajor($oldversion)) {
				info('Major upgrade detected - updating ghost-cli, relaxing permissions');
				// Permission requirements are insanely insecure... otherwise Ghost vomits.
				$this->pman_run(
					'find %(approot)s/ -mindepth 1 -type d -exec chmod 00775 {} \;',
					['approot' => $approot],
					[],
					['user' => $this->getDocrootUser($approot)]
				);
				if (is_debug()) {
					warn("Disabling debug mode as it causes a maxBuffer exceeded error");
					//is_debug() ? '-V' : null;
				}
				// @TODO update LTS?
				if (!$this->_exec($approot, 'nvm exec ghost update %s --local -D --no-restart --no-color --v%d',
					[
						null,
						\Opcenter\Versioning::asMajor($oldversion)
					])) {
					return error('Failed to prep for major version upgrade');
				}

				return error('Ghost upgrade must be manually completed. Run the following command to use the migration assistant: ' .
					'cd %s && NODE_ENV=production nvm exec ghost update --local -f', $approot);
			}
			// force version assertion on incomplete upgrade
			$this->assertLocalVersion($approot, $oldversion, $version);
			// more bad permission requirements, -D bypasses chmod requirement

			$cmd = 'nvm exec ghost update %(debug)s --no-restart -D --local --no-prompt --no-color %(version)s';
			// disable debug mode for now, causes stdout maxBuffer exceeded error
			if (is_debug()) {
				warn("Disabling debug mode as it causes a maxBuffer exceeded error");
				//is_debug() ? '-V' : null;
			}
			$args['debug'] = null;
			$args['version'] = $version;
			$ret = $this->_exec($approot, $cmd, $args);
			$this->fixSymlink($approot);
			$this->file_touch("${approot}/tmp/restart.txt");

			if (!$ret['success']) {
				$this->setInfo($this->getDocumentRoot($hostname, $path), [
					'version' => $this->get_version($hostname, $path),
					'failed'  => true
				]);

				$this->assertLocalVersion($approot, $oldversion, $version);

				return error('failed to update Ghost: %s', coalesce($ret['stderr'], $ret['stdout']));
			}

			$ret = $this->migrate($approot) && ($this->kill($hostname, $path) || true);

			if ($version !== ($newver = $this->get_version($hostname, $path))) {
				report("Upgrade failed, reported version `%s' is not requested version `%s'", $newver, $version);
			}
			$this->setInfo($this->getDocumentRoot($hostname, $path), [
				'version' => $newver,
				'failed'  => !$ret
			]);

			return $ret;
		}

		/**
		 * Assert local Ghost CLI version matches expected
		 *
		 * @param string $approot
		 * @param string $version
		 * @return bool true if assertion passes, false if change forced
		 */
		private function assertLocalVersion(string $approot, string $version, string $targetVersion = null): bool
		{
			$json = $this->file_get_file_contents($approot . '/.ghost-cli');
			$meta = json_decode($json, true);
			if (!is_array($meta)) {
				return error("Failed decoding meta in `%s': %s", $approot, json_last_error_msg());
			}

			if ($targetVersion) {
				$stat = $this->file_stat($approot . '/versions/' . $targetVersion);
				if ($stat && $stat['referent']) {
					$this->file_delete($approot . '/versions/' . $targetVersion);
				}
			}

			if (($myver = array_get($meta, 'active-version')) === $version) {
				return true;
			}

			info("Version in %(approot)s reported as %(oldver)s - forcing version as %(newver)s",
				['approot' => $approot, 'oldver' => $myver, 'newver' => $version]);
			$meta['active-version'] = $version;

			return $this->file_put_file_contents($approot . '/.ghost-cli', json_encode($meta), true) > 0;
		}

		/**
		 * Get all available Ghost versions
		 *
		 * @return array
		 */
		public function get_versions(): array
		{
			$versions = $this->_getVersions();

			return array_column($versions, 'version');
		}

		public function get_installable_versions(): array
		{

			return array_filter($this->get_versions(), [$this, 'platformVersionCheck']);
		}

		/**
		 * Ghost version supported by platform
		 *
		 * @param string $version
		 * @return bool
		 */
		private function platformVersionCheck(string $version): bool
		{
			// Ghost v5+ requires MySQL v8
			return version_compare($version, '5.21', '<') || version_compare($version, '5.24.0', '>=');
		}

		/**
		 * Get all current major versions
		 *
		 * @return array
		 */
		private function _getVersions(): array
		{
			$key = 'ghost.versions';
			$cache = Cache_Super_Global::spawn();
			if (false !== ($ver = $cache->get($key))) {
				return (array)$ver;
			}
			$versions = array_filter((new Webapps\VersionFetcher\Github)->fetch('TryGhost/Ghost'), static function($item) {
				if ($item['version'] === '5.45.0') {
					return false;
				}
				return version_compare($item['version'], '5.0.0', '<') || version_compare($item['version'], '5.24.1', '>=');
			});

			$cache->set($key, $versions, 43200);

			return $versions;
		}

		/**
		 * Update plugins
		 *
		 * @param string $hostname domain or subdomain
		 * @param string $path     optional path within host
		 * @param array  $plugins
		 * @return bool
		 */
		public function update_plugins(string $hostname, string $path = '', array $plugins = array()): bool
		{
			return error('not implemented');
		}

		/**
		 * Update Laravel themes
		 *
		 * @param string $hostname subdomain or domain
		 * @param string $path     optional path under hostname
		 * @param array  $themes
		 * @return bool
		 */
		public function update_themes(string $hostname, string $path = '', array $themes = array()): bool
		{
			return error('not implemented');
		}

		/**
		 * @inheritDoc
		 */
		public function has_fortification(string $hostname, string $path = '', string $mode = null): bool
		{
			return false;
		}

		/**
		 * Restrict write-access by the app
		 *
		 * @param string $hostname
		 * @param string $path
		 * @param string $mode
		 * @param array  $args
		 * @return bool
		 */
		public function fortify(string $hostname, string $path = '', string $mode = 'max', $args = []): bool
		{
			return error('not implemented');
		}

		/**
		 * Relax permissions to allow write-access
		 *
		 * @param string $hostname
		 * @param string $path
		 * @return bool
		 * @internal param string $mode
		 */
		public function unfortify(string $hostname, string $path = ''): bool
		{
			return error('not implemented');
		}
	}


