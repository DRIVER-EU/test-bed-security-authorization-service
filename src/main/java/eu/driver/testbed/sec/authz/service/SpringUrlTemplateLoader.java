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
