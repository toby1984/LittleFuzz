package de.codesourcery.littlefuzz.core;

/**
 * Responsible for assigning a value to the {@link Fuzzer.IContext#getField() current field}.
 *
 * @author tobias.gierke@voipfuture.com
 */
@FunctionalInterface
public interface IFieldSetter
{
    /**
     * Assign value to {@link Fuzzer.IContext#getField() current field}
     * @param value value to assign
     * @throws IllegalAccessException if assigning the field changed
     */
    void set(Object value) throws IllegalAccessException;
}
