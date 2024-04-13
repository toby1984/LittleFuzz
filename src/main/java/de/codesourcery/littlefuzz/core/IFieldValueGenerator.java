package de.codesourcery.littlefuzz.core;

/**
 * Provides a new value for a given field.
 *
 * @author tobias.gierke@code-sourcery.de
 */
@FunctionalInterface
public interface IFieldValueGenerator
{
    /**
     * Generate a new field value.
     *
     * @param context context information
     * @return new field value to assign
     * @throws IllegalAccessException may be thrown if implementation tries to access the current field and fails.
     */
    Object getValue(Fuzzer.IContext context) throws IllegalAccessException;
}
