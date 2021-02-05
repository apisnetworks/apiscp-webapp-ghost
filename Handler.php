<?php
	/**
 * Copyright (C) Apis Networks, Inc - All Rights Reserved.
 *
 * Unauthorized copying of this file, via any medium, is
 * strictly prohibited without consent. Any dissemination of
 * material herein is prohibited.
 *
 * For licensing inquiries email <licensing@apisnetworks.com>
 *
 * Written by Matt Saladna <matt@apisnetworks.com>, August 2020
 */

	namespace Module\Support\Webapps\App\Type\Ghost;

	use Module\Support\Webapps\App\Type\Passenger\Handler as Passenger;

	class Handler extends Passenger
	{
		const NAME = 'Ghost';
		const ADMIN_PATH = '/ghost';
		const LINK = 'https://ghost.org/';

		const FEAT_ALLOW_SSL = true;
		const FEAT_RECOVERY = false;

		public function changePassword(string $password): bool
		{
			return $this->ghost_change_admin($this->hostname, $this->path, ['password' => $password]);
		}

		public function getInstallableVersions(): array
		{
			return array_filter(parent::getInstallableVersions(), static function ($version) {
				return false === strpos($version, '-');
			});
		}


	}