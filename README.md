
![Build Status](https://github.com/toby1984/LittleFuzz/actions/workflows/maven.yml/badge.svg)

## LittleFuzz

A tiny (no external dependencies) reflection-based fuzzer written in Java, perfect for unit-testing. 
Its purpose is to assign random values to object properties (out of the box, methods and fields are supported) 
using customizable value generation and property discovery strategies. 

### Requirements (using)

You need to be running at least JDK 17

### Requirements (building)

JDK 17, Maven 3.9.6 or later

To publish to Maven Central, use `mvn -Prelease release:prepare release:perform`.

### Usage

Assuming you're using Maven, add this to your pom.xml

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-full</artifactId>
      <version>1.0.5</version>
    </dependency>

If you don't care about the support classes (see below) that come with the full package, use 'littlefuzz-core' only:

    <dependency>
      <groupId>de.code-sourcery.littlefuzz</groupId>
      <artifactId>littlefuzz-core</artifactId>
      <version>1.0.5</version>
    </dependency>

#### Getting started

First, you'll have to create an instance of the `de.codesourcery.littlefuzz.core.Fuzzer`:

    Fuzzer fuzzer = new Fuzzer();

By default, only member fields will be available for fuzzing. You can change this via the `setPropertyResolver(IPropertyResolver)`
method and, for example, assign a `MethodResolver` instead - or implement your own. 
You may want to wrap the property resolver using a `CachingPropertyResolver` so that the expensive property resolution
process is not run more often than necessary.

Then you can register fuzzing rules (`de.codesourcery.littlefuzz.core.IFuzzingRule`) based on a property's 
declaring class and name or based on the property type using the `addPropertyRule()` , `setPropertyRule()`, 
`addTypeRule()` and `setTypeRule()` methods.

The difference between the `addXXX()` and `setXXX()` rules is that the `addXXX()` methods will fail when trying to
to register a rule more than once for any given type/property while the `setXXX()` methods will just overwrite any
rule that may have been already assigned.

        fuzzer.addPropertyRule( SomeClass.class, "b", (context, setter) -> {} );
        // a rule that just unconditionally increments the properties' value by one
        fuzzer.addTypeRule( (context,setter) -> setter.set( (int) context.getPropertyValue() + 1), Integer.TYPE);

To decide how to randomize a property value, the following algorithm is used:

1. Check if a fuzzing rule with the property's name and declaring class exists. If it does, use that rule.
2. Check if there's a fuzzing rule matching the property's type. If it does, use that rule. 
3. Throw a `RuntimeException` complaining that no rule for a property could be found.

You can change this via the `setRuleResolver(IRuleResolver)` method. If you need to fuzz values for a lot of different types,
check out `RecursiveRuleResolver` that will automatically instantiate POJO classes and recursively fuzz them.

Finally, you're ready to fuzz an object:

    fuzzer.fuzz( myObject );
    // fuzzer.fuzz( myObject, false ); // if property resolution should not consider inherited properties

# Core vs Full

The littlefuzz-full module contains some helpers that are build on top of the 'core' classes:

- `DifferentValueGenerator`: A wrapper for `IPropertyValueGenerator` instances that makes sure the newly assigned value is never equal to the current property value
- `RandimUtils`: Helper functions (like selecting N random values out of a Java `Collection` etc) to generate property values based on a `java.util.RandomGenerator`.