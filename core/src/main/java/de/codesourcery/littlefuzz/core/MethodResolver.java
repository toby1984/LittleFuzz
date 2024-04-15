package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * A {@link IPropertyResolver} that looks for non-static methods.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class MethodResolver implements IPropertyResolver
{
    protected boolean isValidGetter(Method m) {
        return m.getName().startsWith("get") && m.getParameterTypes().length == 0 && m.getReturnType() != void.class;
    }

    protected boolean isValidSetter(Method m) {
        return m.getName().startsWith("set") && m.getParameterTypes().length == 1;
    }

    @Override
    public List<IProperty> getProperties(Class<?> clazz, boolean includeInherited)
    {
        final List<IProperty> result = new ArrayList<>();
        Class<?> current = clazz;
        do
        {
            final Map<String,Method> getters = new HashMap<>();
            final Map<String,Method> setters = new HashMap<>();
            for ( final Method f : current.getDeclaredMethods() )
            {
                if ( isSuitableMethod( f ) )
                {
                    if ( isValidGetter(f)) {
                        getters.put( f.getName().substring( 3 ).toLowerCase(), f );
                    } else if ( isValidSetter( f ) ) {
                        setters.put( f.getName().substring( 3 ).toLowerCase(), f );
                    }
                }
            }
            for ( final Map.Entry<String, Method> entry : setters.entrySet() )
            {
                final Method getter = getters.get( entry.getKey() );
                entry.getValue().setAccessible( true );
                getter.setAccessible( true );
                result.add( new MethodProperty( entry.getKey(), getter, entry.getValue() ) );
            }
            current = current.getSuperclass();
        }  while (includeInherited && current != Object.class );
        return result;
    }

    protected boolean isSuitableMethod(Method f)
    {
        return Modifier.isPublic( f.getModifiers() )
            && !Modifier.isStatic( f.getModifiers() )
            && !Modifier.isAbstract( f.getModifiers() )
            && !Modifier.isNative( f.getModifiers() );
    }
}
