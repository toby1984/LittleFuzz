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

import java.lang.reflect.Field;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.apache.commons.lang3.Validate;

/**
 * Wraps another {@link IFieldResolver} to add caching of resolved fields.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class CachingFieldResolver implements IFieldResolver
{
    private final IFieldResolver delegate;

    private record CacheKey(Class<?> clazz, boolean includeInherited) { }

    private final Map<CacheKey,List<Field>> cache = new HashMap<>();

    public CachingFieldResolver(IFieldResolver delegate)
    {
        Validate.notNull( delegate, "delegate must not be null" );
        this.delegate = delegate;
    }

    /**
     * Wraps another {@link IFieldResolver} to add caching of resolved fields.
     *
     * @param resolver resolver to wrap
     * @return caching instance.
     */
    public static CachingFieldResolver wrap(IFieldResolver resolver) {
        return new CachingFieldResolver( resolver );
    }

    @Override
    public List<Field> getFields(Class<?> clazz, boolean includeInherited)
    {
        final CacheKey key = new CacheKey( clazz, includeInherited );
        List<Field> result = cache.get( key );
        if ( result == null ) {
            result = delegate.getFields( clazz, includeInherited );
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
     * Returns the field resolver that's wrapped by this instance.
     *
     * @return delegate, never <code>null</code>
     */
    public IFieldResolver getDelegate()
    {
        return delegate;
    }
}
