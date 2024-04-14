package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Field;
import java.lang.reflect.Modifier;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * A {@link IPropertyResolver} that looks for non-static member fields.
 *
 * @author tobias.gierke@code-sourcery.de
 */
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
                if ( isSuitableField( f ) )
                {
                    fields.add( new FieldProperty( f ) );
                }
            }
            current = current.getSuperclass();
        }  while (includeInherited && current != Object.class );
        return fields;
    }

    protected boolean isSuitableField(Field f)
    {
        return !Modifier.isStatic( f.getModifiers() ) && !THIS_PTR.matcher( f.getName() ).matches();
    }
}
