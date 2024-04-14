package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Method;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class MethodResolver implements IPropertyResolver
{
    private static boolean isValidGetter(Method m) {
        return m.getName().startsWith("get") && m.getParameterTypes().length == 0 && m.getReturnType() != void.class;
    }

    private static boolean isValidSetter(Method m) {
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
                if ( Modifier.isPublic( f.getModifiers() )
                       && ! Modifier.isStatic( f.getModifiers() )
                       && ! Modifier.isAbstract( f.getModifiers() )
                       && ! Modifier.isNative( f.getModifiers() )
                     )
                {
                    if ( isValidGetter(f)) {
                        getters.put( f.getName().substring( 3 ).toLowerCase(), f );
                    } else if ( isValidSetter( f ) ) {
                        setters.put( f.getName().substring( 3 ).toLowerCase(), f );
                    }
                }
            }
            for ( final Map.Entry<String, Method> setter : setters.entrySet() )
            {
                final Method getter = getters.get( setter.getKey() );
                result.add( new MethodProperty( setter.getKey(), getter, setter.getValue() ) );
            }
            current = current.getSuperclass();
        }  while (includeInherited && current != Object.class );
        return result;
    }
}