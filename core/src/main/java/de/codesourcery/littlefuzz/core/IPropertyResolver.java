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

import java.util.List;

/**
 * Returns all {@link IProperty properties} that need fuzzing for a given class.
 *
 * @author tobias.gierke@code-sourcery.de
 *
 * @see IProperty
 * @see CachingPropertyResolver
 */
public interface IPropertyResolver
{
    /**
     * Returns the properties to fuzz for a given class.
     *
     * @param clazz the class to resolve properties for, never
     * @param includeInherited whether to also look for members of super classes
     * @return list of properties that should be assigned random values
     */
    List<IProperty> getProperties(Class<?> clazz, boolean includeInherited);
}
