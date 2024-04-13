package de.codesourcery.littlefuzz.core;

import java.lang.reflect.Field;
import java.util.List;

/**
 * Returns all {@link Field member fields} for a given class.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public interface IFieldResolver
{
    /**
     * Returns the fields to fuzz for a given class.
     *
     * @param clazz            the class to get fields for, never
     * @param includeInherited whether to also return fields from super-classes
     * @return list of fields that should be assigned random values
     */
    List<Field> getFields(Class<?> clazz, boolean includeInherited);
}
