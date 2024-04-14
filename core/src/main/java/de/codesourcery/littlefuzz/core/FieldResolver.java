package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

public class FieldResolver implements IPropertyResolver
{
    private static final Pattern THIS_PTR = Pattern.compile( "^this\\$\\d+$" );

    @Override
    public List<IProperty> getProperties(Class<?> clazz, boolean includeInherited)
    {
        final List<IProperty> fields = new ArrayList<>();
        Class<?> current = clazz;
        do
        {
            for ( final Field f : current.getDeclaredFields() )
            {
                if ( ! Modifier.isStatic( f.getModifiers() ) && ! THIS_PTR.matcher( f.getName() ).matches() )
                {
                    fields.add( new FieldProperty( f ) );
                }
            }
            current = current.getSuperclass();
        }  while (includeInherited && current != Object.class );
        return fields;
    }
}
