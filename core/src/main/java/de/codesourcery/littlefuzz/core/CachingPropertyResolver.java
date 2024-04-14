/*
 * Copyright © 2024 Tobias Gierke (tobias.gierke@code-sourcery.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package de.codesourcery.littlefuzz.core;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.Validate;

/**
 * Wraps another {@link IPropertyResolver} to add caching of resolved properties.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class CachingPropertyResolver implements IPropertyResolver
{
    private final IPropertyResolver delegate;

    private record CacheKey(Class<?> clazz, boolean includeInherited) { }

    private final Map<CacheKey,List<IProperty>> cache = new HashMap<>();

    public CachingPropertyResolver(IPropertyResolver delegate)
    {
        Validate.notNull( delegate, "delegate must not be null" );
        this.delegate = delegate;
    }

    /**
     * Wraps another {@link IPropertyResolver} to add caching of resolved properties.
     *
     * @param resolver resolver to wrap
     * @return caching instance.
     */
    public static CachingPropertyResolver wrap(IPropertyResolver resolver) {
        return new CachingPropertyResolver( resolver );
    }

    @Override
    public List<IProperty> getProperties(Class<?> clazz, boolean includeInherited)
    {
        final CacheKey key = new CacheKey( clazz, includeInherited );
        List<IProperty> result = cache.get( key );
        if ( result == null ) {
            result = delegate.getProperties( clazz , includeInherited);
            cache.put( key, result );
        }
        return result;
    }

    /**
     * Clears the cache.
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Returns the property resolver that's wrapped by this instance.
     *
     * @return delegate, never <code>null</code>
     */
    public IPropertyResolver getDelegate()
    {
        return delegate;
    }
}
