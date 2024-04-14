package de.codesourcery.littlefuzz.core;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import org.apache.commons.lang3.Validate;

public class MethodProperty implements IProperty
{
    private final Method getterMethod;
    private final Method setterMethod;
    private final String propertyName;

    /**
     * Create instance.
     *
     * @param propertyName property name
     * @param getterMethod getter method, may be <code>NULL</code>.
     * @param setterMethod setter method, never <code>NULL</code>
     */
    public MethodProperty(String propertyName, Method getterMethod, Method setterMethod)
    {
        Validate.notBlank( propertyName, "propertyName must not be null or blank");
        Validate.notNull( setterMethod, "setterMethod must not be null" );

        this.getterMethod = getterMethod;
        this.setterMethod = setterMethod;
        this.propertyName = propertyName;
    }

    @Override
    public Class<?> getDeclaringClass()
    {
        return getterMethod.getDeclaringClass();
    }

    @Override
    public Class<?> getType()
    {
        return getterMethod.getReturnType();
    }

    @Override
    public String getName()
    {
        return propertyName;
    }

    @Override
    public void setValue(Object target, Object value)
    {
        try
        {
            setterMethod.invoke( target, value );
        }
        catch( IllegalAccessException | InvocationTargetException e )
        {
            throw new RuntimeException( e );
        }
    }

    @Override
    public Object getValue(Object target)
    {
        if ( getterMethod == null ) {
            throw new IllegalStateException( "Cannot retrieve value for property '" + propertyName + "' from "
                + getDeclaringClass() + " - found no suitable getter method " );
        }
        try
        {
            return getterMethod.invoke( target );
        }
        catch( IllegalAccessException | InvocationTargetException e )
        {
            throw new RuntimeException( e );
        }
    }
}
