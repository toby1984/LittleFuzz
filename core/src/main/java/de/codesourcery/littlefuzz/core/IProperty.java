package de.codesourcery.littlefuzz.core;

/**
 * A property that can be assigned using a {@link IFuzzingRule}.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public interface IProperty
{
    Class<?> getDeclaringClass();

    Class<?> getType();

    String getName();

    void setValue(Object target, Object value);

    Object getValue(Object target);
}
