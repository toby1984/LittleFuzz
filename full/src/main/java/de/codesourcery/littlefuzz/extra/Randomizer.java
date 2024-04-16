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
package de.codesourcery.littlefuzz.extra;

import java.time.ZoneId;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
import java.util.function.Supplier;
import java.util.random.RandomGenerator;
import org.apache.commons.lang3.Validate;
import de.codesourcery.littlefuzz.core.Fuzzer;
import de.codesourcery.littlefuzz.core.IPropertyValueGenerator;
import de.codesourcery.littlefuzz.core.IFuzzingRule;

/**
 * Helper functions to generate randomized property values using a {@link RandomGenerator}
 * as sourcee of randomness.
 *
 * @author tobias.gierke@code-sourcery.de
 */
public class Randomizer
{
    /** Default set of characters to use when generating random strings */
    public static final char[] DEFAULT_CHARS = "abcdefghijklmnopqrstuvwxyz0123456789".toCharArray();

    private final RandomGenerator randomGenerator;

    public Randomizer(RandomGenerator randomGenerator)
    {
        Validate.notNull( randomGenerator, "randomGenerator must not be null" );
        this.randomGenerator = randomGenerator;
    }

    /**
     * Picks a random value from an enumeration.
     *
     * @param enumClass enum to pick values from
     * @return random value or <code>Optional.empty()</code> if the enumeration has no values at all
     */
    public Optional<Object> pickRandomEnumValue(Class<?> enumClass) {
        Validate.notNull( enumClass, "enumClass must not be null" );
        Validate.isTrue( enumClass.isEnum(), "Not an enum class: "+enumClass);

        final Object[] values = enumClass.getEnumConstants();
        if ( values.length == 0 ) {
            return Optional.empty();
        }
        final int idx = randomGenerator.nextInt( 0, values.length );
        return Optional.of( values[idx] );
    }

    /**
     * Randomly picks a certain number of distinct elements from a given collection.
     *
     * @param collection collection to pick elements from
     * @param noElementsToPick number of elements to pick
     * @param repetitionAllowed whether the same element may be picked more than once
     * @return a list containing the selected elements
     * @param <T> collection type
     */
    public <T> List<T> pickRandomElements(Collection<T> collection, int noElementsToPick, boolean repetitionAllowed) {

        noElementsToPick = Math.min( collection.size(), noElementsToPick );
        if ( noElementsToPick == 0 ) {
            return new ArrayList<>(0);
        }

        final List<T> result = new ArrayList<>(noElementsToPick);
        if ( repetitionAllowed ) {

            if ( collection instanceof List<T> list) {
                while (result.size() < noElementsToPick)
                {
                    final int idx = randomGenerator.nextInt( 0, list.size() );
                    result.add( list.get( idx ) );
                }
            }
            else {
                while (result.size() < noElementsToPick)
                {
                    final Iterator<T> it = collection.iterator();
                    while (it.hasNext() && result.size() < noElementsToPick)
                    {
                        final T obj = it.next();
                        if ( randomGenerator.nextBoolean() )
                        {
                            result.add( obj );
                        }
                    }
                }
            }
            return result;
        }
        final Set<Integer> alreadyPicked = new HashSet<>();

        if ( collection instanceof List<T> list) {
            while (result.size() < noElementsToPick)
            {
                final int idx = randomGenerator.nextInt( 0, list.size() );
                if ( ! alreadyPicked.contains( idx ) )
                {
                    alreadyPicked.add( idx );
                    result.add( list.get( idx ) );
                }
            }
        }
        else
        {
            while (result.size() < noElementsToPick)
            {
                final Iterator<T> it = collection.iterator();
                int idx = 0;
                while (it.hasNext() && result.size() < noElementsToPick)
                {
                    final T obj = it.next();
                    if ( randomGenerator.nextBoolean() && ! alreadyPicked.contains( idx ) )
                    {
                        alreadyPicked.add( idx );
                        result.add( obj );
                    }
                    idx++;
                }
            }
        }
        return result;
    }

    /**
     * Creates a map with random strings.
     *
     * @param minKeyLen min. length of map keys
     * @param maxKeyLen max. length of map keys
     * @param minValueLen min. length of map values
     * @param maxValueLen max. length of map values
     * @return random map
     */
    public Map<String,String> createRandomStringMap(int minKeyLen, int maxKeyLen, int minValueLen, int maxValueLen) {
        final int size = randomGenerator.nextInt( 1, 30 );
        final Map<String, String> map = new HashMap<>();
        for ( int i = 0 ; i < size ; i++ ) {
            final String key = createRandomString( minKeyLen, maxKeyLen );
            final String value = createRandomString( minValueLen, maxValueLen );
            map.put( key, value );
        }
        return map;
    }

    /**
     * Creates a random string with a random length.
     * @param minLen minimum length the string should have (inclusive)
     * @param maxLen maximum length the string should have (inclusive)
     * @return random string
     */
    public String createRandomString(int minLen, int maxLen) {
        return createRandomString( minLen, maxLen, DEFAULT_CHARS );
    }
    /**
     * Creates a random string with a random length.
     * @param minLen minimum length the string should have (inclusive)
     * @param maxLen maximum length the string should have (inclusive)
     * @param chars set of characters to create random string from.
     * @return random string
     */
    public String createRandomString(int minLen, int maxLen, char[] chars) {
        Validate.isTrue( minLen >= 0 );
        Validate.isTrue( maxLen >= minLen );
        Validate.isTrue( chars != null && chars.length > 0 , "need at least one character to choose from");

        final int len = minLen == maxLen ? minLen : minLen + randomGenerator.nextInt( maxLen - minLen -1 );
        final StringBuilder buffer = new StringBuilder();
        for ( int i = len ; i > 0 ; i-- ) {
            buffer.append( DEFAULT_CHARS[randomGenerator.nextInt( 0, DEFAULT_CHARS.length )] );
        }
        return buffer.toString();
    }

    /**
     * Clears all property and type rules and sets up default rules for JDK built-in datatypes.
     *
     * <p>
     * Rules that use this classes {@link RandomGenerator} get registered for byte/short/int/long/float/double/boolean
     * and their respective wrapper object types.
     * </p>
     * <p>
     * Additionally, rules for {@link java.time.Instant} and {@link ZonedDateTime} are registered as well but
     * those again just rely on {@link RandomGenerator#nextLong()}.
     * </p>
     * <p>
     * A rule for {@link java.lang.String} is added as well that will assign a string of random length [1,20]
     * using random characters out the {@link #DEFAULT_CHARS} array, again relying on this classes {@link RandomGenerator}.
     * </p>
     *
     * @param wrapperGenerator optional function to wrap the default property value generators before registering
     *                         them. May be <code>null</code> to not perform any wrapping at all.
     * @see DifferentValueGenerator#wrap(IPropertyValueGenerator)
     */
    public void setupDefaultRules(Fuzzer fuzzer, Function<Supplier<?>, IPropertyValueGenerator> wrapperGenerator) {

        if ( wrapperGenerator == null ) {
            wrapperGenerator = (toWrap) -> (ctx) -> toWrap.get();
        }

        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> createRandomString( 1,20 ) ) ), String.class );
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextLong ) ), Long.class, Long.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextInt ) ), Integer.class, Integer.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> (short) randomGenerator.nextInt() ) ), Short.class, Short.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextFloat ) ), Float.class, Float.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextDouble ) ), Double.class, Double.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> (byte) randomGenerator.nextInt() ) ), Byte.class, Byte.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( randomGenerator::nextBoolean ) ), Boolean.class, Boolean.TYPE);
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> java.time.Instant.ofEpochMilli( randomGenerator.nextLong() ) ) ), java.time.Instant.class );
        fuzzer.addTypeRule( IFuzzingRule.fromSupplier( wrapperGenerator.apply( () -> java.time.Instant.ofEpochMilli( randomGenerator.nextLong() ).atZone( ZoneId.systemDefault() ) ) ), ZonedDateTime.class  );
    }

    /**
     * Returns the random generator used by this class.
     *
     * @return random generator, never <code>null</code>
     * @see #Randomizer(RandomGenerator)
     */
    public RandomGenerator getRandomGenerator()
    {
        return randomGenerator;
    }
}
