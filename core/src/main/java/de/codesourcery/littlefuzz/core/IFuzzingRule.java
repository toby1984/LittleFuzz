package de.codesourcery.littlefuzz.core;

import java.util.function.Supplier;

/**
 * Generates a new value for given field and applies it (if desired/applicable).
 *
 * @author tobias.gierke@code-sourcery.de
 */
@FunctionalInterface
public interface IFuzzingRule
{

    /**
     * A no-op rule that does nothing.
     */
    IFuzzingRule NOP_RULE = (fieldInfo, setter) -> {};

    /**
     * Creates a rule that assigns a value from a {@link Supplier}.
     *
     * @param supplier provides the value to assign
     * @return the rule using that supplier
     * @see #fromSupplier(IFieldValueGenerator)
     */
    static IFuzzingRule fromSupplier(Supplier<?> supplier)
    {
        return (context, setter) -> setter.set( supplier.get() );
    }

    /**
     * Creates a rule that assigns a value from a {@link IFieldValueGenerator}.
     *
     * @param supplier provides the value to assign
     * @return the rule using that supplier
     * @see #fromSupplier(Supplier)
     */
    static IFuzzingRule fromSupplier(IFieldValueGenerator supplier)
    {
        return (context, setter) -> setter.set( supplier.getValue( context ) );
    }

    /**
     * Fuzz a given field.
     *
     * @param context information about field that should be assigned etc.
     * @param setter  setter that should be used to assign the field a new value
     * @throws IllegalAccessException reflection...
     */
    void fuzz(Fuzzer.IContext context, IFieldSetter setter) throws IllegalAccessException;
}
