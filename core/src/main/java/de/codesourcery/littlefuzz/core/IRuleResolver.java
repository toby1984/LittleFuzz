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

/**
 * Locates the rule to use for a given property.
 *
 * @author tobias.gierke@code-sourcery.de
 */
@FunctionalInterface
public interface IRuleResolver
{
    /**
     * Resolve the fuzzing rule for the {@link Fuzzer.IContext#getProperty() current property}.
     *
     * <p>
     * This method should throw an exception if no suitable fuzzing rule could be located.
     * </p>
     *
     * @param context context
     * @return fuzzing rule to use or <code>null</code> if no suitable rule could be located.
     */
    IFuzzingRule getRule(Fuzzer.IContext context);
}
