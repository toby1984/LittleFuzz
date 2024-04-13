package de.codesourcery.littlefuzz.core;

/**
 * Locates the rule to use for a given field.
 *
 * @author tobias.gierke@code-sourcery.de
 */
@FunctionalInterface
public interface IRuleResolver
{
    /**
     * Resolve the fuzzing rule for the {@link Fuzzer.IContext#getField() current field}.
     *
     * <p>
     * This method should throw an exception if no suitable fuzzing rule could be located.
     * </p>
     *
     * @param context context
     * @return fuzzing rule to use, never <code>null</code>
     */
    IFuzzingRule getRule(Fuzzer.IContext context);
}
