/**
 * Copyright (C) 2012-2018 Thales Services SAS.
 *
 * This file is part of AuthzForce CE.
 *
 * AuthzForce CE is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * AuthzForce CE is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with AuthzForce CE.  If not, see <http://www.gnu.org/licenses/>.
 */
package eu.driver.testbed.sec.authz.service;

import java.io.FileNotFoundException;
import java.net.URL;

import org.springframework.util.ResourceUtils;

import freemarker.cache.URLTemplateLoader;

/**
 * Spring-like URL template loader
 */
public final class SpringUrlTemplateLoader extends URLTemplateLoader
{

	@Override
	protected URL getURL(final String name)
	{
		try
		{
			return ResourceUtils.getURL(name);
		}
		catch (final FileNotFoundException e)
		{
			throw new RuntimeException("Failed to load Freemarker template: ", e);
		}
	}

}
