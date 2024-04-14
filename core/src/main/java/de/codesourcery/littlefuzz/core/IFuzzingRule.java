/*
 * Copyright © 2024 Tobias Gierke (tobias.gierke@code-sourcery.de)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
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
    @SuppressWarnings("unused")
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
     */
    void fuzz(Fuzzer.IContext context, IFieldSetter setter);
}
