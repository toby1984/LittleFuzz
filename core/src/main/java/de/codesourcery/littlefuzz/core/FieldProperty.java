package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Field;
import org.apache.commons.lang3.Validate;

/**
 * A {@link IProperty} that maps to a {@link java.lang.reflect.Field}.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class FieldProperty implements IProperty
{
    private final Field field;

    public FieldProperty(Field field)
    {
        Validate.notNull( field, "field must not be null" );
        this.field = field;
        this.field.setAccessible( true );
    }

    @Override
    public Class<?> getDeclaringClass()
    {
        return field.getDeclaringClass();
    }

    @Override
    public Class<?> getType()
    {
        return field.getType();
    }

    @Override
    public String getName()
    {
        return field.getName();
    }

    @Override
    public void setValue(Object target, Object value)
    {
        try
        {
            field.set( target, value );
        }
        catch( IllegalAccessException e )
        {
            throw new RuntimeException( e );
        }
    }

    @Override
    public Object getValue(Object target)
    {
        try
        {
            return field.get( target );
        }
        catch( IllegalAccessException e )
        {
            throw new RuntimeException( e );
        }
    }

    @Override
    public String toString()
    {
        return "Field '" + getName() + "' with type " + getType().getName() + " of " + getDeclaringClass().getName();
    }
}
